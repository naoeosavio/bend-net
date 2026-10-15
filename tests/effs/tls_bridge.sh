#!/usr/bin/env bash
# TLS bridge gate (task-043-js-lane-tls-pure, phase 0): the shape of the
# JS lane bridge, with the numbers that chose it.
#
# Checks:
#   probe  the park bridge end to end in the interp lane, against a
#          loopback TLS server: ALPN negotiated, the echo comes back, and
#          the runtime keeps serving other computations (a 150 ms delay
#          on the server shows as ~0 ms of tick starvation).
#   block  mode 1 (Atomics.wait) blocks the loop: with the server in the
#          same process the whole program hangs, so the check expects the
#          timeout. It is the measurement that rejected mode 1.
#   lane   the same bridge in the emitted `-o x.js` lane under bun.
#   worker TLS inside a worker, under node and bun (the dependency).
#   adopt  an fd cannot cross threads: node adopts the io_sys style fd,
#          bun refuses it. Informative -- it records a platform gap.
#
# Usage: tests/effs/tls_bridge.sh
set -u

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root" || exit 1

bend_bin="${BEND:-bend}"
bun_bin="${BUN:-bun}"
node_bin="${NODE:-node}"
probe="tests/effs/bridge/bridge_probe.bend"
bridge="tests/effs/bridge"
pass=0
fail=0

ok() { pass=$((pass + 1)); printf 'PASS %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }

# Reads one JSON field out of a line: field <json> <name>.
field() {
  printf '%s' "$1" | sed -n "s/.*\"$2\":\([^,}]*\).*/\1/p" | tr -d '"'
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# A free loopback port, for the openssl peer below.
free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); \
print(s.getsockname()[1]); s.close()'
}

# The bridge end to end in one lane. $1 = label, $2... = command.
bridge_check() {
  local label="$1" so="$work/$1.out" se="$work/$1.err" st json ticks stall
  shift
  timeout 60 "$@" >"$so" 2>"$se"
  st=$?
  json="$(grep -a '"mode"' "$se" | tail -n 1)"
  if [ "$st" -ne 0 ]; then
    bad "$label exits $st"
    return
  fi
  if [ "$(field "$json" alpn)" != "2" ]; then
    bad "$label ALPN: got $json"
    return
  fi
  if [ "$(field "$json" head)" != "hello" ]; then
    bad "$label echo: got $json"
    return
  fi
  # The server delays 150 ms before accepting, so a bridge that blocks
  # the loop would starve the ticker for about that long.
  ticks="$(grep -ac '^t' "$so")"
  stall="$(awk '/^t/{v=substr($0,2)+0; if(v>m) m=v} END{print m+0}' "$so")"
  if [ "$ticks" -lt 50 ]; then
    bad "$label ticker only ran $ticks ticks"
    return
  fi
  if [ "$stall" -gt 40 ]; then
    bad "$label the loop was held for ${stall}ms (park is not cooperative)"
    return
  fi
  ok "$label alpn http/1.1, echo back, max tick overshoot ${stall}ms"
}

# 1) The bridge in the interp lane (Bun inside bend).
bridge_check "probe interp" "$bend_bin" "$probe"

# 2) Mode 1 must hang: Atomics.wait freezes the loop, and the server of
#    this very program lives on that loop.
so="$work/block.out"
timeout 20 env P0_MODE=1 "$bend_bin" "$probe" >"$so" 2>&1
if [ $? -eq 124 ]; then
  ok "block mode 1 (Atomics.wait) hangs a same-process server, as measured"
else
  bad "block mode 1 finished: the loop was not held"
fi

# 3) The emitted JS lane, under bun. It needs bun >= 1.4.3: on 1.2.15 the
#    worker's TLS write callback fires and the loopback peer never sees
#    the bytes, so the lane hangs (measured 2026-10-12, same probe).
bun_ver="$("$bun_bin" --version 2>/dev/null | head -n 1)"
if [ "$(printf '%s\n1.4.3\n' "$bun_ver" | sort -V | head -n 1)" = "1.4.3" ]; then
  if "$bend_bin" "$probe" -o "$work/probe.js" >/dev/null 2>&1; then
    bridge_check "lane bun" "$bun_bin" "$work/probe.js"
  else
    bad "lane cannot emit $probe"
  fi
else
  printf 'SKIP %s\n' "lane bun $bun_ver < 1.4.3 (measured: hangs the echo)"
fi

# 4) TLS inside a worker, under node and bun, against a local openssl
#    peer (self-signed test cert, so no network is needed).
port="$(free_port)"
openssl s_server -quiet -accept "$port" -cert tests/io/tls_test_cert.pem \
  -key tests/io/tls_test_key.pem -alpn http/1.1 -naccept 2 \
  >"$work/s_server.log" 2>&1 &
srv=$!
for rt in "$node_bin" "$bun_bin"; do
  name="$(basename "$rt")"
  line="$(timeout 30 env P0_PORT="$port" P0_HOST=localhost \
    P0_IP=127.0.0.1 "$rt" "$bridge/worker_tls.js" \
    2>"$work/worker_$name.err" | tail -n 1)"
  case "$(field "$line" ok)" in
    true)
      if [ "$(field "$line" alpn)" = "http/1.1" ]; then
        ok "worker $name handshake in $(field "$line" ms_handshake)ms"
      else
        bad "worker $name ALPN: $line"
      fi
      ;;
    *)
      bad "worker $name: $line $(tail -n 1 "$work/worker_$name.err")"
      ;;
  esac
done
kill "$srv" 2>/dev/null
wait "$srv" 2>/dev/null

# 5) fd adoption: node takes an inherited connected fd, bun refuses it.
#    Informative for bun (the refusal is why the worker dials its own
#    socket), required for node.
adopt() {
  local rt="$1" name line
  name="$(basename "$rt")"
  line="$(python3 - "$rt" "$bridge/fd_adopt.js" <<'PY'
import os, socket, subprocess, sys, threading, time
rt, script = sys.argv[1], sys.argv[2]
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(1)
cli = socket.create_connection(srv.getsockname(), timeout=3)
conn, _ = srv.accept()
os.set_inheritable(cli.fileno(), True)
env = dict(os.environ, P0_FD=str(cli.fileno()))
p = subprocess.Popen([rt, script], env=env, stdout=subprocess.PIPE,
                     stderr=subprocess.DEVNULL, text=True,
                     pass_fds=(cli.fileno(),))
conn.sendall(b"pong")
try:
    out, _ = p.communicate(timeout=10)
except subprocess.TimeoutExpired:
    p.kill()
    out, _ = p.communicate()
print(out.strip().splitlines()[-1] if out.strip() else "")
PY
)"
  printf '%s\n' "$name $line"
}

line="$(adopt "$node_bin")"
case "$line" in
  *'"head":"pong"'*) ok "adopt node takes the fd" ;;
  *) bad "adopt node: $line" ;;
esac
line="$(adopt "$bun_bin")"
case "$line" in
  *'Socket is closed'*|*'"timeout":true'*|*'"error"'*)
    printf 'NOTE %s\n' "adopt bun refuses the fd ($line) -- the worker dials instead"
    ;;
  *'"head":"pong"'*)
    printf 'NOTE %s\n' "adopt bun now takes the fd: revisit the bridge decision"
    ;;
  *) bad "adopt bun: $line" ;;
esac

printf '=== %d passed, %d failed ===\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
