/* util_parse_fuzzer: SPDK util string/number/address/mask/encoding parsers (lib/util). */
#include "spdk/stdinc.h"
#include "spdk/base64.h"
#include "spdk/cpuset.h"
#include "spdk/hexlify.h"
#include "spdk/string.h"
#include "spdk/uuid.h"

#define MAX_INPUT_LEN 4096

static void
fuzz_base64(const char *str, const uint8_t *raw, size_t raw_len, bool urlsafe)
{
	size_t dlen = 0;
	size_t cap = spdk_base64_get_decoded_len(strlen(str));
	uint8_t *dec = malloc(cap ? cap : 1);
	char *enc;

	if (dec == NULL) {
		return;
	}
	if ((urlsafe ? spdk_base64_urlsafe_decode(dec, &dlen, str) : spdk_base64_decode(dec, &dlen, str)) == 0) {
		if (dlen > cap) {
			abort();
		}
	}
	free(dec);

	if (raw_len == 0) {
		return;
	}
	enc = malloc(spdk_base64_get_encoded_strlen(raw_len) + 1);
	dec = malloc(raw_len + 3);
	if (enc != NULL && dec != NULL) {
		int rc = urlsafe ? spdk_base64_urlsafe_encode(enc, raw, raw_len) : spdk_base64_encode(enc, raw, raw_len);

		if (rc != 0) {
			abort();
		}
		rc = urlsafe ? spdk_base64_urlsafe_decode(dec, &dlen, enc) : spdk_base64_decode(dec, &dlen, enc);
		if (rc != 0 || dlen != raw_len || memcmp(dec, raw, raw_len) != 0) {
			abort();
		}
	}
	free(enc);
	free(dec);
}

static void
fuzz_hex(const char *str, const uint8_t *raw, size_t raw_len)
{
	char *bin = spdk_unhexlify(str);
	char *hex;

	free(bin);
	hex = spdk_hexlify((const char *)raw, raw_len);
	if (hex != NULL) {
		bin = spdk_unhexlify(hex);
		if (bin == NULL || memcmp(bin, raw, raw_len) != 0) {
			abort();
		}
		free(bin);
		free(hex);
	}
}

static void
fuzz_cpuset(const char *str)
{
	struct spdk_cpuset *a = spdk_cpuset_alloc();
	struct spdk_cpuset *b = spdk_cpuset_alloc();

	if (a != NULL && b != NULL) {
		if (spdk_cpuset_parse(a, str) == 0) {
			spdk_cpuset_count(a);
			spdk_cpuset_fmt(a);
			spdk_cpuset_copy(b, a);
			spdk_cpuset_negate(b);
			spdk_cpuset_or(b, a);
			spdk_cpuset_xor(b, a);
		}
	}
	spdk_cpuset_free(a);
	spdk_cpuset_free(b);
}

static void
fuzz_string(const char *str, size_t len)
{
	char *tmp, *p, *q;
	char **arr;
	uint64_t cap;
	bool pfx;
	char dst[64];

	spdk_strtol(str, 0);
	spdk_strtol(str, 10);
	spdk_strtoll(str, 16);
	spdk_parse_capacity(str, &cap, &pfx);

	tmp = strdup(str);
	if (tmp != NULL) {
		spdk_str_trim(tmp);
		spdk_str_chomp(tmp);
		spdk_strlwr(tmp);
		free(tmp);
	}

	tmp = strdup(str);
	if (tmp != NULL) {
		char *host = NULL, *port = NULL;

		spdk_parse_ip_addr(tmp, &host, &port);
		free(tmp);
	}

	tmp = strdup(str);
	if (tmp != NULL) {
		p = tmp;
		while ((q = spdk_strsepq(&p, ",;")) != NULL) {
			(void)q;
		}
		free(tmp);
	}

	arr = spdk_strarray_from_string(str, ", ");
	if (arr != NULL) {
		spdk_strarray_free(arr);
	}

	spdk_strcpy_replace(dst, sizeof(dst), str, "a", "bcd");
	spdk_strcpy_pad(dst, str, sizeof(dst), ' ');
	spdk_strlen_pad(dst, sizeof(dst), ' ');
	spdk_mem_all_zero(str, len);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct spdk_uuid uuid;
	char *str;
	uint8_t sel;

	if (size < 1 || size > MAX_INPUT_LEN) {
		return -1;
	}

	sel = data[0] % 7;
	data++;
	size--;

	str = malloc(size + 1);
	if (str == NULL) {
		return -1;
	}
	memcpy(str, data, size);
	str[size] = '\0';

	switch (sel) {
	case 0:
		fuzz_base64(str, data, size, false);
		break;
	case 1:
		fuzz_base64(str, data, size, true);
		break;
	case 2:
		fuzz_hex(str, data, size);
		break;
	case 3:
		fuzz_cpuset(str);
		break;
	case 4:
		spdk_uuid_parse(&uuid, str);
		break;
	default:
		fuzz_string(str, size);
		break;
	}

	free(str);
	return 0;
}
