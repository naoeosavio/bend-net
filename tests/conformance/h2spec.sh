#!/usr/bin/env bash
# The H2 conformance gate (task-071 phase 4). It builds the stress server
# from examples/httpx/stress_h2.bend, runs h2spec 2.6.0 against it and
# compares the failed tests with tests/conformance/h2spec.expected.
#
# Exit codes: 0 no failure outside the expected list, 1 a new failure, 2
# the tool is missing, the port is busy, the server did not start or the
# server stopped mid-run in three attempts. A test of the expected list
# that now passes is printed and does not fail the run.
#
# The server of this box stops accepting after some connections
# (task-073). The script proves each run with a fresh-connection probe and
# repeats a run that died in the middle, so the list measures the module
# and not the defect.
#
# Use the official h2spec 2.6.0 release. A binary built from the same
# commit with a newer Go shows 7 false failures (docs/h2spec.md).
# The run needs a quiet machine: the server is pure Bend over TLS, and a
# loaded CPU makes the tests that this box still shows fail.
set -u

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)" || exit 1
cd "$root" || exit 1

bend_bin="${BEND:-bend}"
port="${H2SPEC_PORT:-18960}"
spec_bin="${H2SPEC:-$(command -v h2spec || true)}"
if [ -z "$spec_bin" ] && [ -x .scratch/h2spec-bin ]; then
  spec_bin=".scratch/h2spec-bin"
fi
if [ -z "$spec_bin" ]; then
  printf 'h2spec not found: install 2.6.0 or set H2SPEC\n' >&2
  exit 2
fi

work="$(mktemp -d)" || exit 1
srv_pid=""

cleanup() {
  if [ -n "$srv_pid" ]; then
    kill "$srv_pid" 2>/dev/null
    wait "$srv_pid" 2>/dev/null
  fi
  rm -rf "$work"
}
trap cleanup EXIT

# The native build is slow (about 8 minutes on one core), so print the
# step first and let the caller see where the run is.
bin="$work/stress_h2"
printf 'build %s\n' "$bin"
if ! "$bend_bin" examples/httpx/stress_h2.bend -o "$bin" \
  > "$work/build.log" 2>&1; then
  printf 'the build failed:\n' >&2
  tail -20 "$work/build.log" >&2
  exit 2
fi

if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
  printf 'port %s is busy: stop the other server\n' "$port" >&2
  exit 2
fi

printf 'serve 127.0.0.1:%s\n' "$port"

# One server per attempt. task-073 makes the server stop accepting after
# some connections, so a run can die in the middle and report failures
# that the module does not have. A fresh connection that gets the server
# SETTINGS proves that the run was whole; a failed probe repeats the run
# with a new server.
start_server() {
  "$bin" ok >> "$work/server.log" 2>&1 &
  srv_pid=$!
  for _ in $(seq 1 100); do
    grep -q LISTEN "$work/server.log" 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}

stop_server() {
  if [ -n "$srv_pid" ]; then
    kill "$srv_pid" 2>/dev/null
    wait "$srv_pid" 2>/dev/null
    srv_pid=""
  fi
  for _ in $(seq 1 50); do
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null || return 0
    sleep 0.1
  done
  return 1
}

attempt=1
while : ; do
  : > "$work/server.log"
  if ! start_server; then
    printf 'the server did not start:\n' >&2
    cat "$work/server.log" >&2
    exit 2
  fi

  printf 'run h2spec (attempt %s)\n' "$attempt"
  # h2spec exits 1 when a test fails; the report is the result that counts.
  "$spec_bin" -h 127.0.0.1 -p "$port" -t -k --timeout 3 \
    -j "$work/report.xml" > "$work/h2spec.log" 2>&1
  # Liveness probe: a fresh connection must get the server SETTINGS.
  probe_ok=""
  if "$spec_bin" http2/3.5 -h 127.0.0.1 -p "$port" -t -k --timeout 3 \
    > "$work/probe.log" 2>&1; then
    probe_ok="1"
  fi
  stop_server

  if [ -z "$probe_ok" ]; then
    attempt=$((attempt + 1))
    if [ "$attempt" -gt 3 ]; then
      printf 'the server stopped after 3 runs: see task-073\n' >&2
      tail -5 "$work/probe.log" >&2
      exit 2
    fi
    printf 'the server stopped mid-run: retry with a new server\n'
    continue
  fi
  break
done

if [ ! -s "$work/report.xml" ]; then
  printf 'h2spec wrote no report:\n' >&2
  tail -20 "$work/h2spec.log" >&2
  exit 2
fi

# The failed test of each suite, as "<package> | <test case>". The
# indented XML puts the attributes of one testcase on one line and its
# failure element on the next lines, so the case name stays from line to
# line. h2spec writes a failure element for a wrong answer and an error
# element for a broken connection; both count.
got="$work/failed.txt"
awk '
  /<testsuite / {
    pkg = ""
    if (match($0, /package="[^"]*"/)) {
      pkg = substr($0, RSTART + 9, RLENGTH - 10)
    }
  }
  /<testcase / {
    name = ""
    if (match($0, /classname="[^"]*"/)) {
      name = substr($0, RSTART + 11, RLENGTH - 12)
    }
    case_key = pkg " | " name
  }
  /<failure>|<error>/ {
    print case_key
  }
' "$work/report.xml" | sort -u > "$got"

want="$work/want.txt"
grep -vE '^[[:space:]]*(#|$)' tests/conformance/h2spec.expected |
  sed 's/[[:space:]]*$//' | sort -u > "$want"

# tests/conformance/h2spec.expected is the list of known failures, not a
# list of runs that must fail again. A known failure that now passes is
# news, and the run continues. A failure that is not listed fails the
# gate, so the list holds every failure this box still shows.
new="$work/new.txt"
fixed="$work/fixed.txt"
if [ -s "$want" ]; then
  grep -Fxv -f "$want" "$got" > "$new" || true
  grep -Fxv -f "$got" "$want" > "$fixed" || true
else
  cp "$got" "$new"
  : > "$fixed"
fi

if [ -s "$fixed" ]; then
  printf 'now passing, remove the line from h2spec.expected:\n'
  sed 's/^/  /' "$fixed"
fi
if [ -s "$new" ]; then
  printf 'new failures:\n' >&2
  sed 's/^/  /' "$new" >&2
  exit 1
fi
printf 'h2spec: no new failure, %s known failure(s)\n' \
  "$(wc -l < "$want" | tr -d ' ')"
exit 0
