/* json_decode_fuzzer: SPDK JSON number conversion and typed object/array decoders (lib/json/json_util.c). */
#include "spdk/stdinc.h"
#include "spdk/json.h"
#include "spdk/util.h"

#define MAX_JSON_VALUES 4096

struct decoded {
	uint32_t count;
	int32_t delta;
	uint64_t big;
	uint16_t port;
	uint8_t level;
	bool enabled;
	char *name;
};

static const struct spdk_json_object_decoder g_decoders[] = {
	{"count", offsetof(struct decoded, count), spdk_json_decode_uint32, true},
	{"delta", offsetof(struct decoded, delta), spdk_json_decode_int32, true},
	{"big", offsetof(struct decoded, big), spdk_json_decode_uint64, true},
	{"port", offsetof(struct decoded, port), spdk_json_decode_uint16, true},
	{"level", offsetof(struct decoded, level), spdk_json_decode_uint8, true},
	{"enabled", offsetof(struct decoded, enabled), spdk_json_decode_bool, true},
	{"name", offsetof(struct decoded, name), spdk_json_decode_string, true},
};

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct spdk_json_val *values;
	struct decoded out;
	uint8_t *buf;
	ssize_t n;
	size_t i, cnt;
	uint32_t arr[8];

	if (size < 1) {
		return -1;
	}

	buf = malloc(size);
	if (buf == NULL) {
		return -1;
	}
	memcpy(buf, data, size);

	n = spdk_json_parse(buf, size, NULL, 0, NULL, 0);
	if (n <= 0 || n > MAX_JSON_VALUES) {
		free(buf);
		return -1;
	}
	values = calloc(n, sizeof(*values));
	if (values == NULL) {
		free(buf);
		return -1;
	}
	if (spdk_json_parse(buf, size, values, n, NULL, 0) != n) {
		abort();
	}

	for (i = 0; i < (size_t)n; i++) {
		if (values[i].type == SPDK_JSON_VAL_NUMBER) {
			uint8_t u8;
			uint16_t u16;
			int32_t i32;
			uint32_t u32;
			uint64_t u64;

			spdk_json_number_to_uint8(&values[i], &u8);
			spdk_json_number_to_uint16(&values[i], &u16);
			spdk_json_number_to_int32(&values[i], &i32);
			spdk_json_number_to_uint32(&values[i], &u32);
			spdk_json_number_to_uint64(&values[i], &u64);
		}
	}

	if (values[0].type == SPDK_JSON_VAL_OBJECT_BEGIN) {
		memset(&out, 0, sizeof(out));
		spdk_json_decode_object(values, g_decoders, SPDK_COUNTOF(g_decoders), &out);
		spdk_json_free_object(g_decoders, SPDK_COUNTOF(g_decoders), &out);

		memset(&out, 0, sizeof(out));
		spdk_json_decode_object_relaxed(values, g_decoders, SPDK_COUNTOF(g_decoders), &out);
		spdk_json_free_object(g_decoders, SPDK_COUNTOF(g_decoders), &out);
	} else if (values[0].type == SPDK_JSON_VAL_ARRAY_BEGIN) {
		cnt = 0;
		spdk_json_decode_array(values, spdk_json_decode_uint32, arr, SPDK_COUNTOF(arr), &cnt,
				       sizeof(arr[0]));
	}

	free(values);
	free(buf);
	return 0;
}
