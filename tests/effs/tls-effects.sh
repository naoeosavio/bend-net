#!/usr/bin/env bash
# Interop ladder for the tls-effects package (task-046): the five effects
# over the host's native `tls`, in TLS 1.3 AND TLS 1.2, measured against
# OpenSSL as the reference peer -- in Node AND in Bun.
#
# The peer is always the system `openssl`, never the host's own `tls`
# under test: testing our effect against the same stack it calls would
# only prove the host agrees with itself. The one exception is named
# `cross`, where the peer is the *other* host on purpose -- there the
# question is whether a bun-built effect and a node-built effect still
# interoperate.
#
# Rungs (each one run under every host in $HOSTS):
#   smoke     both effects in one process: handshake, ALPN, ping/pong,
#             close
#   client13  our client  -> openssl s_server -tls1_3, ALPN h2 required
#   client12  our client  -> openssl s_server -tls1_2, ECDHE-RSA GCM
#   server13  our server  <- openssl s_client -tls1_3
#   server12  our server  <- openssl s_client -tls1_2, ECDHE-RSA GCM
#   alpn      our client demands h2 against an http/1.1-only peer, and
#             our server offers only h2 against a http/1.1-only peer:
#             both must answer 615, not a generic handshake failure
#   verify    badssl: an untrusted chain must answer 614, not "connect"
#   versions  badssl: tls-v1-1 and tls-v1-0 are 613 (documented out of
#             scope), tls-v1-2 is OK
#   cross     client and server built by different hosts must still talk
#   ffi       zero `bun:ffi` require in this package
#
# Capability: the server rungs need a host that can drive inbound TLS
# from a socket it did not create. Measured 2026-10-12: bun 1.2.15
# cannot (the TLSSocket is built and never handshakes -- D30), bun 1.4.3
# and node can. Those rungs are a versioned SKIP on the hosts that lack
# it, never a silent pass.
#
# Usage: tests/effs/tls-effects.sh           # node + bun
#        HOSTS=node tests/effs/tls-effects.sh
#        BUN=.p42/bun/bun-linux-x64/bun tests/effs/tls-effects.sh
set -u

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root" || exit 1

pkg="tests/effs/tls-effects"
probe="$pkg/scratch/tls_probe.js"
sprobe="$pkg/scratch/tls_server_probe.js"
smoke="$pkg/tests/smoke.js"
node_bin="${NODE:-node}"
bun_bin="${BUN:-bun}"
# "node bun" by default; a missing host falls out of the loop below.
hosts="${HOSTS:-node bun}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

pass=0
fail=0
skip=0

ok() { pass=$((pass + 1)); printf 'PASS %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
skipped() { skip=$((skip + 1)); printf 'SKIP %s\n' "$1"; }
note() { printf 'NOTE %s\n' "$1"; }

# A free loopback port, so parallel runs and leftover sockets cannot
# collide with a fixed number.
free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); \
print(s.getsockname()[1]); s.close()'
}

# Block until something accepts on $1, or give up after ~4s. A refused
# dial is a flake, not a verdict. Only for the openssl peers: the
# throwaway connection closes at once, so s_server moves on to the real
# peer.
wait_port() {
  local port="$1" tries=0
  while [ "$tries" -lt 40 ]; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      exec 3<&- 2>/dev/null || true
      return 0
    fi
    tries=$((tries + 1))
    sleep 0.1
  done
  return 1
}

# Waits for a probe's own "up" line. Polling the port instead would hand
# tls_accept_raw a non-TLS peer: it takes one `connection` event per call
# and would then wait for a ClientHello that never arrives (D31), while
# the real peer sits unaccepted in the backlog.
wait_up() {
  local log="$1" tries=0
  while [ "$tries" -lt 60 ]; do
    if grep -qa '^up' "$log" 2>/dev/null; then
      return 0
    fi
    tries=$((tries + 1))
    sleep 0.1
  done
  return 1
}

# What a server probe last reported, on one line.
said() {
  grep -a '^OK \|^FAIL ' "$1" | tail -n 1
}

# The ALPN a server probe last negotiated.
alpn_of() {
  grep -ao 'alpn="[^"]*"' "$1" | tail -n 1
}

# True when the host binary is on PATH or is a path we can run.
installed() {
  command -v "$1" >/dev/null 2>&1 || [ -x "$1" ]
}

# True when $1 (a version string) is at least $2. The sort trick is the
# one tls_bridge.sh already uses for the same question.
at_least() {
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" = "$2" ]
}

# The minimum bun that can serve TLS from a socket it did not create.
# Measured 2026-10-12 (D30): 1.2.15 builds the TLSSocket and never
# completes the handshake, 1.4.3 completes it.
min_serving_bun="1.4.3"

# True when the host named by $1 ($2 is its binary) can run the server
# rungs.
can_serve() {
  local label="$1" bin="$2" ver
  [ "$label" = "bun" ] || return 0
  ver="$("$bin" --version 2>/dev/null | head -n 1)"
  at_least "$ver" "$min_serving_bun"
}

# Self-signed test material: the ladder is hermetic and must not depend
# on a checked-in cert expiring on a schedule nobody remembers.
openssl req -x509 -newkey rsa:2048 -keyout "$work/k.pem" -out "$work/c.pem" \
  -days 2 -nodes -subj "/CN=localhost" >/dev/null 2>&1 || {
  echo "FAIL cannot create test certificate"; exit 1;
}

# The HTTP request openssl's -www mode expects before it answers. CRLF,
# because that is what the peers on the wire actually speak; printf below
# turns the escapes into the real bytes.
request='GET / HTTP/1.0\r\n\r\n'
# The same request for the probe environment, as head lines only: a shell
# cannot pass a trailing blank line through a variable (command
# substitution strips it), so the probe appends the terminator itself.
request_head='GET / HTTP/1.0'

# ---------------------------------------------------------------------------
# client13 / client12: our client against openssl s_server.
# $1 label, $2 host binary, $3 extra openssl s_server flags, $4 want
client_check() {
  local label="$1" bin="$2" want="$3"
  shift 3
  local port out tries=0
  port="$(free_port)"
  # Key the log on the label: BUN=.p42/bun/... puts slashes in the path
  # and the redirect then fails silently (D28).
  openssl s_server -accept "$port" -cert "$work/c.pem" -key "$work/k.pem" \
    -alpn h2 -www -quiet "$@" >"$work/s_server_$label.log" 2>&1 &
  local srv=$!
  while [ "$tries" -lt 20 ]; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      exec 3<&- 2>/dev/null || true
      break
    fi
    tries=$((tries + 1))
    sleep 0.1
  done
  out="$(P0_REQUEST="$request_head" P0_TIMEOUT_MS=15000 \
    timeout 30 "$bin" "$probe" 127.0.0.1 "$port" 1 0 2>&1)"
  kill "$srv" 2>/dev/null
  wait "$srv" 2>/dev/null
  case "$out" in
    *"OK ver=$want alpn=\"h2\""*)
      ok "$name $label negotiated TLS $want with ALPN h2"
      ;;
    *) bad "$name $label: $out" ;;
  esac
}

# ---------------------------------------------------------------------------
# server13 / server12: openssl s_client against our server. The peer must
# read the answer back, so a half-open handshake cannot pass (D27).
# $1 label, $2 host binary, $3 openssl s_client flag, $4 want, $5 cipher
server_check() {
  local label="$1" bin="$2" flag="$3" want="$4" cipher="$5"
  local port out log
  port="$(free_port)"
  log="$work/srv_${name}_${label}.log"
  "$bin" "$sprobe" "$work/c.pem" "$work/k.pem" "$port" 2 >"$log" 2>&1 &
  local srv=$!
  wait_up "$log"
  out="$(printf "$request" | timeout 30 openssl s_client \
    -connect "127.0.0.1:$port" "$flag" -alpn h2 $cipher -quiet 2>&1)"
  sleep 0.3
  kill "$srv" 2>/dev/null
  wait "$srv" 2>/dev/null
  if printf '%s' "$out" | grep -qa "HTTP/1"; then
    if grep -qa "^OK ver=$want " "$log"; then
      ok "$name $label served TLS $want to openssl s_client"
    else
      bad "$name $label: peer read the answer, our side says $(said "$log")"
    fi
  else
    bad "$name $label: peer got no answer: $(printf '%s' "$out" | tail -n 1)"
  fi
}

# ---------------------------------------------------------------------------
# alpn: a required-protocol that the peer will not satisfy. The contract
# is 615 on both sides -- a generic 612/613 would hide the one cause the
# `alpn` argument exists to report.
# $1 label, $2 host binary, $3 side: client|server
alpn_check() {
  local label="$1" bin="$2" side="$3" port out log srv
  port="$(free_port)"
  log="$work/alpn_${name}_${side}.log"
  if [ "$side" = "client" ]; then
    openssl s_server -accept "$port" -cert "$work/c.pem" -key "$work/k.pem" \
      -alpn http/1.1 -www -quiet -tls1_3 >"$log" 2>&1 &
    srv=$!
    wait_port "$port"
    out="$(P0_TIMEOUT_MS=15000 timeout 30 "$bin" "$probe" \
      127.0.0.1 "$port" 1 0 2>&1)"
    kill "$srv" 2>/dev/null
    wait "$srv" 2>/dev/null
  else
    # The server side speaks first: offer only h2 and read what our own
    # side reports, because the peer's alert arrives on stderr either way.
    "$bin" "$sprobe" "$work/c.pem" "$work/k.pem" "$port" 1 >"$log" 2>&1 &
    srv=$!
    wait_up "$log"
    timeout 30 openssl s_client -connect "127.0.0.1:$port" \
      -tls1_3 -alpn http/1.1 -quiet </dev/null >/dev/null 2>&1
    sleep 0.3
    kill "$srv" 2>/dev/null
    wait "$srv" 2>/dev/null
    out="$(grep -a '^FAIL \|^OK ' "$log" | tail -n 1)"
  fi
  case "$out" in
    *"FAIL 615"*) ok "$name alpn $side answers 615" ;;
    *) bad "$name alpn $side: expected 615, got: $out" ;;
  esac
}

# ---------------------------------------------------------------------------
# verify: badssl hosts that must be refused with 614. A refusal for the
# WRONG reason (dial failure, timeout) would also "not connect", so the
# code is what is asserted.
verify_check() {
  local bin="$1" label="$2" domain="$3" port="$4" want="$5" out
  out="$(P0_TIMEOUT_MS=20000 timeout 40 "$bin" "$probe" "$domain" "$port" \
    1 1 2>&1)"
  case "$out" in
    *"FAIL $want"*) ok "$name verify $label answers $want" ;;
    *"OK "*) bad "$name verify $label was ACCEPTED (must fail closed)" ;;
    *) bad "$name verify $label: expected $want, got: $out" ;;
  esac
}

# The version rung uses mode 3 (http/1.1 only): those endpoints predate
# h2, and an ALPN refusal would mask the version answer.
version_check() {
  local bin="$1" label="$2" domain="$3" port="$4" want="$5" out
  out="$(P0_TIMEOUT_MS=20000 timeout 40 "$bin" "$probe" "$domain" "$port" \
    3 1 2>&1)"
  case "$out" in
    *"OK "*) ok "$name $label handshakes" ;;
    *"FAIL $want"*) ok "$name $label refused with $want (out of scope)" ;;
    *) bad "$name $label: expected OK or $want, got: $out" ;;
  esac
}

# ---------------------------------------------------------------------------
# cross: the two effects built by two different hosts must interoperate.
# $1 label, $2 client binary, $3 server binary
cross_check() {
  local label="$1" cbin="$2" sbin="$3" port out log srv side
  port="$(free_port)"
  log="$work/cross_$label.log"
  side="$(basename "$cbin") client to $(basename "$sbin") server"
  "$sbin" "$sprobe" "$work/c.pem" "$work/k.pem" "$port" 2 >"$log" 2>&1 &
  srv=$!
  wait_up "$log"
  out="$(P0_REQUEST="$request_head" P0_TIMEOUT_MS=15000 \
    timeout 30 "$cbin" "$probe" 127.0.0.1 "$port" 1 0 2>&1)"
  sleep 0.3
  kill "$srv" 2>/dev/null
  wait "$srv" 2>/dev/null
  case "$out" in
    *"OK ver="*)
      if grep -qa "^OK ver=" "$log"; then
        ok "$name cross $label: $side, ALPN $(alpn_of "$log")"
      else
        bad "$name cross $label: client OK but server said $(said "$log")"
      fi
      ;;
    *) bad "$name cross $label: $side: $out" ;;
  esac
}

# A peer that answers, so "the ladder has no network" is never confused
# with "every rung below it failed for the network's sake".
have_network() {
  timeout 10 openssl s_client -connect badssl.com:443 -servername badssl.com \
    </dev/null >/dev/null 2>&1
}

# ---------------------------------------------------------------------------

printf '=== hosts: %s ===\n' "$hosts"

for host in $hosts; do
  bin="$node_bin"
  [ "$host" = "bun" ] && bin="$bun_bin"
  name="$host"
  if ! installed "$bin"; then
    skipped "$name not installed"
    continue
  fi
  ver="$("$bin" --version 2>/dev/null | head -n 1)"
  note "$name $ver"

  # The round trip needs both effects in one process, so it needs the
  # server capability as well.
  no_serve="needs inbound TLS from a foreign socket"
  if can_serve "$name" "$bin"; then
    if out="$(P0_TIMEOUT_MS=20000 timeout 60 "$bin" "$smoke" 2>&1)"; then
      ok "$name smoke: handshake, ALPN, ping/pong, close"
    else
      bad "$name smoke: $out"
    fi
  else
    skipped "$name smoke ($no_serve, bun >= $min_serving_bun)"
  fi

  client_check "client13" "$bin" 1.3 -tls1_3
  client_check "client12" "$bin" 1.2 -tls1_2 \
    -cipher ECDHE-RSA-AES128-GCM-SHA256

  # Every rung below needs the same capability, so it gates them all.
  if can_serve "$name" "$bin"; then
    server_check "server13" "$bin" -tls1_3 1.3 ""
    server_check "server12" "$bin" -tls1_2 1.2 \
      "-cipher ECDHE-RSA-AES128-GCM-SHA256"
  else
    skipped "$name server13/server12 ($no_serve, bun >= $min_serving_bun)"
  fi

  alpn_check client "$bin" client
  if can_serve "$name" "$bin"; then
    alpn_check server "$bin" server
  else
    skipped "$name alpn server ($no_serve, bun >= $min_serving_bun)"
  fi

  if have_network; then
    verify_check "$bin" "self-signed" self-signed.badssl.com 443 614
    verify_check "$bin" "wrong.host" wrong.host.badssl.com 443 614
    verify_check "$bin" "untrusted-root" untrusted-root.badssl.com 443 614
    verify_check "$bin" "expired" expired.badssl.com 443 614
    version_check "$bin" "tls-v1-2" tls-v1-2.badssl.com 1012 613
    version_check "$bin" "tls-v1-1" tls-v1-1.badssl.com 1011 613
    version_check "$bin" "tls-v1-0" tls-v1-0.badssl.com 1010 613
  else
    skipped "$name badssl rungs (no network: DNS or egress unavailable)"
  fi
done

# The crossed legs, outside the per-host loop: each ordered pair of
# hosts serves one leg, and a pair that shares a host is already covered
# by the client/server rungs above. A host that is not installed, or
# cannot serve, is a SKIP with the reason -- never a silent pass.
crossed=0
for c in $hosts; do
  for s in $hosts; do
    [ "$c" = "$s" ] && continue
    cbin="$node_bin"; [ "$c" = "bun" ] && cbin="$bun_bin"
    sbin="$node_bin"; [ "$s" = "bun" ] && sbin="$bun_bin"
    if ! installed "$cbin" || ! installed "$sbin"; then
      skipped "cross $c to $s (a host is not installed)"
    elif ! can_serve "$s" "$sbin"; then
      skipped "cross $c to $s (serving side needs bun >= $min_serving_bun)"
    else
      crossed=$((crossed + 1))
      cross_check "$c-$s" "$cbin" "$sbin"
    fi
  done
done
if [ "$crossed" -eq 0 ]; then
  skipped "cross rungs (needs two hosts installed and serving)"
fi

# bun:ffi must be gone from this package: it is the native toolchain the
# pure-JS lane replaced, and one stray require brings a compiler back.
# Only source files are counted -- a README or a task file that NAMES the
# dependency in prose is documentation, not a dependency.
ffi_count="$(grep -rn --include='*.js' --include='*.c' --include='*.bend' \
  'require("bun:ffi")\|require(.bun:ffi.)' "$pkg" 2>/dev/null |
  wc -l | tr -d ' ')"
if [ "$ffi_count" = "0" ]; then
  ok "no bun:ffi require in the tls-effects package"
else
  bad "bun:ffi require found in the tls-effects package ($ffi_count sites)"
  grep -rn --include='*.js' 'require("bun:ffi")' "$pkg" 2>/dev/null | head -5
fi

# Does lib/ still carry a bun:ffi twin? Reported, not failed: this task's
# scope is the package, and task-043-js-lane-tls-pure owns that debt (its
# phase 5). Comment lines are skipped, the same way the package check
# above skips them: a design note that names the old dependency is not a
# dependency. The debt is paid as of 2026-10-15 (the only mention left is
# a history note in lib/effs/dns_resolve.js), so the rung passes.
ffi_re='require("bun:ffi")'
lib_ffi="$(grep -n -e "$ffi_re" lib/effs/*.js 2>/dev/null |
  grep -v -e ':[0-9]*: *//' | cut -d: -f1 | sort -u | grep -c .)"
if [ "$lib_ffi" = "0" ]; then
  ok "lib/ is off bun:ffi too"
else
  note "lib/ still has $lib_ffi bun:ffi twins (task-043-js-lane-tls-pure)"
fi

printf '=== %d passed, %d failed, %d skipped ===\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]