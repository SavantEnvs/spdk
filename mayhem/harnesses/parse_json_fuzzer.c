/* parse_json_fuzzer: SPDK JSON parser, finders, string/bool decoders and writer (OSS-Fuzz harness name).
 * Number conversion lives in json_decode_fuzzer. */
#include "spdk/stdinc.h"
#include "spdk/json.h"

#define MAX_VALUES 4096

struct sink {
	size_t len;
	uint8_t last;
};

static int
sink_cb(void *ctx, const void *data, size_t size)
{
	struct sink *s = ctx;

	s->len += size;
	if (size > 0) {
		s->last = ((const uint8_t *)data)[size - 1];
	}
	return 0;
}

static void
exercise_value(const struct spdk_json_val *v)
{
	bool b;
	char *s = NULL;

	spdk_json_val_len(v);
	spdk_json_array_count(v);
	spdk_json_strequal(v, "method");
	if (v->type == SPDK_JSON_VAL_TRUE || v->type == SPDK_JSON_VAL_FALSE) {
		spdk_json_decode_bool(v, &b);
	} else if (v->type == SPDK_JSON_VAL_STRING || v->type == SPDK_JSON_VAL_NAME) {
		s = spdk_json_strdup(v);
		free(s);
		s = NULL;
		if (spdk_json_decode_string(v, &s) == 0) {
			free(s);
		}
	}
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct spdk_json_val *values;
	struct spdk_json_write_ctx *w;
	struct sink sink = {0};
	uint8_t *buf;
	void *end;
	ssize_t n;
	uint32_t flags, wflags;
	size_t i;

	if (size < 1) {
		return -1;
	}

	/* First byte selects parse + write flags; the rest is the JSON text. */
	flags = data[0] & 0x3;
	wflags = (data[0] >> 2) & 0x3;
	data++;
	size--;

	/* spdk_json_parse() decodes in place and does not NUL-terminate: exact-size copy. */
	buf = malloc(size ? size : 1);
	if (buf == NULL) {
		return -1;
	}
	memcpy(buf, data, size);

	n = spdk_json_parse(buf, size, NULL, 0, NULL, flags);
	if (n <= 0 || n > MAX_VALUES) {
		free(buf);
		return -1;
	}

	values = calloc(n, sizeof(*values));
	if (values == NULL) {
		free(buf);
		return -1;
	}

	/* The counting pass may have decoded strings in place (documented): re-parse a pristine copy. */
	memcpy(buf, data, size);
	if (spdk_json_parse(buf, size, values, n, &end, flags) != n) {
		abort();
	}

	for (i = 0; i < (size_t)n; i++) {
		exercise_value(&values[i]);
	}

	if (values[0].type == SPDK_JSON_VAL_OBJECT_BEGIN) {
		struct spdk_json_val *key, *val;

		spdk_json_find(values, "method", &key, &val, SPDK_JSON_VAL_ANY);
		spdk_json_find_string(values, "name", &key, &val);
		spdk_json_find_array(values, "params", &key, &val);
		spdk_json_object_first(values);
	} else if (values[0].type == SPDK_JSON_VAL_ARRAY_BEGIN) {
		spdk_json_array_first(values);
	}

	w = spdk_json_write_begin(sink_cb, &sink, (wflags & 1) ? SPDK_JSON_WRITE_FLAG_FORMATTED : 0);
	if (w != NULL) {
		spdk_json_write_val(w, values);
		spdk_json_write_end(w);
	}

	free(values);
	free(buf);
	return 0;
}
