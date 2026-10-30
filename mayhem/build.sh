#!/usr/bin/env bash
#
# mayhem/build.sh — build the SPDK fuzz harnesses and the upstream CUnit unit tests.
#
# SPDK's json/jsonrpc/util/log libraries compile standalone with clang straight from lib/*.c: no
# ./configure, no DPDK, no submodules, no network. The only generated input is include/spdk/config.h,
# which we write into the build dir (not the source tree), so the tree stays untouched.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

OUT=/mayhem
GEN="$OUT/build/gen"            # generated include/spdk/config.h
FUZZ="$OUT/build/fuzz"          # sanitized library objects
TEST="$OUT/build/test"          # normal-flag library objects for the unit tests
UT="$OUT/build-tests"           # unit-test binaries run by test.sh
rm -rf "$OUT/build" "$UT"
mkdir -p "$GEN/spdk" "$FUZZ" "$TEST" "$UT"

cat > "$GEN/spdk/config.h" <<'H'
#ifndef SPDK_CONFIG_H
#define SPDK_CONFIG_H
#define SPDK_CONFIG_HAVE_LIBUUID 1
#define SPDK_CONFIG_HAVE_UUID_GENERATE_SHA1 1
#endif
H

LIBS="lib/json/json_parse lib/json/json_util lib/json/json_write
      lib/jsonrpc/jsonrpc_server
      lib/log/log lib/log/log_flags
      lib/util/string lib/util/base64 lib/util/hexlify lib/util/cpuset lib/util/uuid
      lib/util/math lib/util/net lib/util/strerror_tls"
INC="-I$GEN -I$SRC/include -I$SRC/lib -I$SRC/test"

# 1) The fuzzed libraries, instrumented, with DWARF <= 3 (libFuzzer coverage via fuzzer-no-link).
FUZZ_CFLAGS="$INC -D_GNU_SOURCE -O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -w"
for f in $LIBS; do
  echo "$f"
done | xargs -P "$MAYHEM_JOBS" -I{} sh -c '"$CC" $0 -c "$SRC/{}.c" -o "$1/$(basename {}).o"' "$FUZZ_CFLAGS" "$FUZZ"
ar rcs "$FUZZ/libspdk_fuzz.a" "$FUZZ"/*.o

# 2) Harnesses: libFuzzer binary + non-fuzzer standalone reproducer, both with the LSan-off hook.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$FUZZ/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ/standalone_main.o"
for h in parse_json_fuzzer util_parse_fuzzer json_decode_fuzzer jsonrpc_server_fuzzer; do
  $CC $INC -D_GNU_SOURCE -O1 $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
      "$SRC/mayhem/harnesses/$h.c" "$FUZZ/libspdk_fuzz.a" "$FUZZ/lsan_off.o" \
      -luuid -lpthread -lm -o "$OUT/$h"
  $CC $INC -D_GNU_SOURCE -O1 $SANITIZER_FLAGS $DEBUG_FLAGS \
      "$SRC/mayhem/harnesses/$h.c" "$FUZZ/standalone_main.o" "$FUZZ/libspdk_fuzz.a" "$FUZZ/lsan_off.o" \
      -luuid -lpthread -lm -o "$OUT/$h-standalone"
done

# 3) Upstream CUnit unit tests with NORMAL flags (no sanitizers), built independently of the above.
TEST_CFLAGS="$INC -D_GNU_SOURCE -O2 -w $COVERAGE_FLAGS"
for f in $LIBS; do
  echo "$f"
done | xargs -P "$MAYHEM_JOBS" -I{} sh -c '"$CC" $0 -c "$SRC/{}.c" -o "$1/$(basename {}).o"' "$TEST_CFLAGS" "$TEST"
ar rcs "$TEST/libspdk_test.a" "$TEST"/*.o

# The unit tests #include the library .c file under test, so they link only the *other* libs from the archive.
for t in json/json_parse.c/json_parse_ut json/json_util.c/json_util_ut json/json_write.c/json_write_ut \
         jsonrpc/jsonrpc_server.c/jsonrpc_server_ut log/log.c/log_ut util/base64.c/base64_ut \
         util/cpuset.c/cpuset_ut util/math.c/math_ut util/net.c/net_ut util/string.c/string_ut; do
  $CC $TEST_CFLAGS -DSPDK_UNIT_TEST=1 "$SRC/test/unit/lib/$t.c" "$SRC/lib/ut/ut.c" "$TEST/libspdk_test.a" \
      -lcunit -luuid -lpthread -lm $COVERAGE_FLAGS -o "$UT/$(basename "$t")"
done
