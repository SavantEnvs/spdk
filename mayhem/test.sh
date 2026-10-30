#!/usr/bin/env bash
#
# mayhem/test.sh — run SPDK's own CUnit unit tests for the libraries we fuzz (json, jsonrpc, log, util),
# pre-built by mayhem/build.sh into /mayhem/build-tests (about 1900 assertions across 10 binaries).
# The counts come from each binary's CUnit summary, so a binary that exits 0 without running its tests
# reports nothing and fails the suite.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

UT=/mayhem/build-tests
UNITS="json_parse_ut json_util_ut json_write_ut jsonrpc_server_ut log_ut base64_ut cpuset_ut math_ut net_ut string_ut"
passed=0; failed=0; skipped=0

for u in $UNITS; do
  if [ ! -x "$UT/$u" ]; then
    echo "missing unit test binary $UT/$u (mayhem/build.sh should have built it)" >&2
    failed=$((failed + 1)); continue
  fi
  out=$("$UT/$u" 2>&1); rc=$?
  # CUnit summary row: "tests  <total> <run> <passed> <failed> <inactive>"
  row=$(printf '%s\n' "$out" | awk '$1 == "tests" && NF == 6 && $2 ~ /^[0-9]+$/ {print $2, $3, $4, $5, $6; exit}')
  if [ -z "$row" ]; then
    echo "$u: no CUnit summary in output (rc=$rc)" >&2
    failed=$((failed + 1)); continue
  fi
  read -r total run ok bad inactive <<< "$row"
  [ "$total" -gt 0 ] || { echo "$u: zero tests registered" >&2; failed=$((failed + 1)); continue; }
  [ "$rc" -eq 0 ] || [ "$bad" -gt 0 ] || bad=1
  echo "$u: total=$total run=$run passed=$ok failed=$bad inactive=$inactive"
  passed=$((passed + ok)); failed=$((failed + bad)); skipped=$((skipped + inactive))
done

emit_ctrf "cunit" "$passed" "$failed" "$skipped"
