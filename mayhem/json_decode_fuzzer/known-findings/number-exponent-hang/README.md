# `spdk_json_number_to_*`: unbounded loop on a zero significand with a huge positive exponent

**Reproducer:** `repro.json` (`[0e9223372036854775807]`), fed to `json_decode_fuzzer` (or its
`-standalone` build). It never returns.

**Where:** `lib/json/json_util.c`, `json_number_split()`, the "positive exponent" branch:

```c
while (num->exponent) {
	if (num->significand > (UINT64_MAX / 10)) {
		break;
	}
	num->significand *= 10;
	num->exponent--;
}
```

**Cause:** the loop only stops when the significand would overflow. With a significand of `0` the
product stays `0`, so the loop runs `exponent` times (up to `INT64_MAX`, about 9.2e18 iterations).

**Impact:** any caller of `spdk_json_number_to_{uint8,uint16,int32,uint32,uint64}` or of a
`spdk_json_decode_{uint8,uint16,int32,uint32,uint64}` decoder, for example every JSON-RPC method that
decodes a numeric parameter, can be pinned at 100% CPU forever by one small request such as
`{"count": 0e9223372036854775807}`. That makes it a remote denial of service on the RPC socket.

**Upstream fix (one line):** stop when the significand is zero:
`while (num->exponent && num->significand != 0)` (the value is then 0 regardless of the exponent).
