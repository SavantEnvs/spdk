/* jsonrpc_server_fuzzer: SPDK JSON-RPC 2.0 server request parser, single and batch (lib/jsonrpc). */
#include "jsonrpc/jsonrpc_internal.h"
#include "spdk/util.h"

#define MAX_PENDING 8192

struct pending {
	struct spdk_jsonrpc_request *request;
	int error;
	const struct spdk_json_val *params;
};

static struct pending g_pending[MAX_PENDING];
static size_t g_num_pending;
static struct spdk_jsonrpc_server g_server;
static struct spdk_jsonrpc_server_conn *g_conn;

static void
queue_request(struct spdk_jsonrpc_request *request, int error, const struct spdk_json_val *params)
{
	if (g_num_pending == MAX_PENDING) {
		abort();
	}
	g_pending[g_num_pending].request = request;
	g_pending[g_num_pending].error = error;
	g_pending[g_num_pending].params = params;
	g_num_pending++;
}

void
jsonrpc_server_handle_error(struct spdk_jsonrpc_request *request, int error)
{
	queue_request(request, error, NULL);
}

void
jsonrpc_server_handle_request(struct spdk_jsonrpc_request *request,
			      const struct spdk_json_val *method, const struct spdk_json_val *params)
{
	(void)method;
	queue_request(request, 0, params);
}

void
jsonrpc_server_send_response(struct spdk_jsonrpc_request *request)
{
	jsonrpc_complete_request(request);
}

static void
respond_all(void)
{
	struct spdk_json_write_ctx *w;
	size_t i;

	for (i = 0; i < g_num_pending; i++) {
		struct spdk_jsonrpc_request *request = g_pending[i].request;

		if (g_pending[i].error != 0) {
			spdk_jsonrpc_send_error_response_fmt(request, g_pending[i].error, "fuzz error");
		} else if (g_pending[i].params != NULL &&
			   g_pending[i].params->type == SPDK_JSON_VAL_OBJECT_BEGIN) {
			spdk_jsonrpc_send_bool_response(request, true);
		} else {
			w = spdk_jsonrpc_begin_result(request);
			spdk_json_write_string(w, "ok");
			spdk_jsonrpc_end_result(request, w);
		}
	}
	g_num_pending = 0;
}

static void
drain_send_queue(struct spdk_jsonrpc_server_conn *conn)
{
	struct spdk_jsonrpc_request *request;

	while ((request = STAILQ_FIRST(&conn->send_queue)) != NULL) {
		STAILQ_REMOVE_HEAD(&conn->send_queue, link);
		conn->outstanding_requests--;
		free(request->recv_buffer);
		free(request->values);
		free(request->send_buf);
		free(request);
	}
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	g_conn = calloc(1, sizeof(*g_conn));
	if (g_conn == NULL) {
		abort();
	}
	pthread_spin_init(&g_conn->queue_lock, PTHREAD_PROCESS_PRIVATE);
	STAILQ_INIT(&g_conn->outstanding_queue);
	STAILQ_INIT(&g_conn->send_queue);
	g_conn->server = &g_server;
	g_conn->sockfd = -1;
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	size_t off = 0;
	int iter;

	if (size == 0 || size > SPDK_JSONRPC_RECV_BUF_SIZE) {
		return -1;
	}

	for (iter = 0; iter < 16 && off < size; iter++) {
		int rc = jsonrpc_parse_request(g_conn, data + off, size - off);

		respond_all();
		drain_send_queue(g_conn);
		if (rc <= 0) {
			break;
		}
		off += rc;
	}

	return 0;
}
