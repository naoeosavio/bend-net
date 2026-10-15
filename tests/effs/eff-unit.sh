#!/usr/bin/env bash
# Hermetic unit rungs for the effect twins (task-053).
#
# What bends but has no golden: the JS twins answer fail codes no Bend
# test can reach without the network (DNS 602-605 die in the pure layer
# with 601; the recv window only matters past INT32_MAX). These probes
# load the twins the way the compiler does and pin the tables with
# crafted inputs instead.
#
# Rungs (node only: hermetic logic, no host behaves differently here):
#   dns    the 601-605 table both twins share (task-050 A3), the IPv6
#          skip and the 127.0.0.53 fallback (task-050 A4)
#   clamp  the recv window floor at 1 and clamp at INT32_MAX, plus the
#          611/616 paths (task-051 recv clamp)
#
# Usage: tests/effs/eff-unit.sh
set -u

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root" || exit 1

node_bin="${NODE:-node}"
pass=0
fail=0

ok() { pass=$((pass + 1)); printf 'PASS %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }

if ! command -v "$node_bin" >/dev/null 2>&1; then
  printf 'SKIP eff-unit (node not installed)\n'
  exit 0
fi

for probe in tests/effs/eff-unit-dns.js tests/effs/eff-unit-clamp.js; do
  if out="$("$node_bin" "$probe" 2>&1)"; then
    ok "$probe hermetic vectors green"
  else
    bad "$probe: $(printf '%s' "$out" | grep -a '^FAIL' | head -3 | tr '\n' ' ')"
  fi
done

printf '=== %d passed, %d failed ===\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
