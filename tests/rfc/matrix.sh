#!/usr/bin/env bash
# RFC conformance matrix: pure Bend vectors plus oracle self-checks.
#
# Usage:
#   tests/rfc/matrix.sh                 # full matrix (bend + node + bun)
#   tests/rfc/matrix.sh --pure          # only the pure Bend vectors
#   tests/rfc/matrix.sh --oracles node  # only oracle self-checks (node|bun)
#
# Cells:
#   pure   — bend tests/rfc/rfc_httpx.bend / rfc_wsm.bend,
#            each must print 1.
#   self   — each oracle client vs its own server, under node and bun.
#   cross  — point any oracle client at a Bend server on the same port,
#            e.g. start the Bend H1 server on 19881, then:
#              node tests/rfc/h1_oracle.js client 19881
#   manual — open tests/rfc/browser.html against the plain servers.
set -u

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root" || exit 1

bend_bin="${BEND:-bend}"
pass=0
fail=0

ok() { pass=$((pass + 1)); printf 'PASS %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }

run_pure() {
  for f in tests/rfc/rfc_httpx.bend tests/rfc/rfc_wsm.bend; do
    out="$("$bend_bin" "$f" 2>&1)"
    status=$?
    last="$(printf '%s\n' "$out" | grep -E '^[01]$' | tail -n 1)"
    if [ "$status" -eq 0 ] && [ "$last" = "1" ]; then
      ok "pure $f"
    else
      bad "pure $f (got '$last')"
    fi
  done
}

# self_check <runtime> <oracle> <port> <server-n> <want-done>
self_check() {
  rt="$1"; oracle="$2"; port="$3"; servern="$4"; want="$5"
  "$rt" "tests/rfc/$oracle" server "$port" "$servern" >/tmp/rfc_oracle.log 2>&1 &
  srv=$!
  sleep 1
  if out="$("$rt" "tests/rfc/$oracle" client "$port" 2>&1)"; then
    if printf '%s\n' "$out" | grep -q "DONE $want"; then
      ok "self $rt $oracle"
    else
      bad "self $rt $oracle (no DONE $want)"
    fi
  else
    bad "self $rt $oracle (client failed)"
  fi
  kill "$srv" 2>/dev/null
  wait "$srv" 2>/dev/null
}

run_oracles() {
  rt="$1"
  if ! command -v "$rt" >/dev/null 2>&1; then
    printf 'skip %s: not found\n' "$rt"
    return 0
  fi
  self_check "$rt" h1_oracle.js 19881 3 "3/3"
  self_check "$rt" ws_oracle.js 19884 2 "6/6"
  if [ "$rt" = "node" ]; then
    self_check "$rt" h2_oracle.js 19883 1 "1/1"
  else
    printf 'skip bun h2_oracle: needs node:http2 client\n'
  fi
}

mode="${1:-all}"
case "$mode" in
  --pure) run_pure ;;
  --oracles) run_oracles "${2:-node}" ;;
  all)
    run_pure
    run_oracles node
    run_oracles bun
    ;;
  *) printf 'usage: %s [--pure|--oracles node|bun]\n' "$0"; exit 2 ;;
esac

printf '=== %d passed, %d failed ===\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
