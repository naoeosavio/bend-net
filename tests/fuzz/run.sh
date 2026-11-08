#!/usr/bin/env bash
# Fuzz the H2 frame parser with new seeds until the time budget ends.
#
#   bash tests/fuzz/run.sh [seconds] [rounds]
#
# The program compiles once, then every run is a new seed of the same
# binary: a variant that breaks the parser contract exits non-zero, and
# this loop reports it. The gate runs a fixed short seed through
# tests/fuzz/frames.bend; this script is the long run.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1

secs="${1:-60}"
rounds="${2:-20000}"
bin="${TMPDIR:-/tmp}/h2_fuzz_frames.$$"

if ! bend tests/fuzz/frames.bend -o "$bin" >/dev/null 2>&1; then
  printf 'build failed: tests/fuzz/frames.bend\n' >&2
  exit 2
fi

end=$(( $(date +%s) + secs ))
runs=0
fail=0
while [ "$(date +%s)" -lt "$end" ]; do
  seed=$(( ($(date +%s%N) / 1000000) % 2000000000 ))
  if ! out="$("$bin" "$seed" "$rounds" 2>&1)"; then
    printf 'seed %s FAIL\n%s\n' "$seed" "$out" >&2
    fail=$((fail + 1))
  fi
  runs=$((runs + 1))
done
rm -f "$bin"
printf '%d runs of %d rounds, %d failures\n' "$runs" "$rounds" "$fail"
[ "$fail" -eq 0 ]
