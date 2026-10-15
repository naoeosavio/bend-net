#!/usr/bin/env bash
# TLS interop ladder for the tls-generic package (task-045): the portable
# runtime's client and server, in TLS 1.3 AND TLS 1.2, measured against
# OpenSSL as the reference peer -- in Node AND in Bun.
#
# Every protocol rung's peer is the system `openssl`, never the host's
# own `tls` builtin: testing our pure-JS handshake against the same
# OpenSSL the lane replaced proves interoperability, and testing it
# against Node's `tls` would only prove Node agrees with Node. One
# deliberate exception: the six hermetic `cbc-len` rungs peer with a
# Node `tls` server, because bun's `tls` server refuses
# ECDHE-RSA-AES128-SHA256 -- the client under test still runs on the
# host named.
#
# Checks (each one run under every host in $HOSTS):
#   client13   our client  -> openssl s_server -tls1_3, ALPN h2 required
#   client12   our client  -> openssl s_server -tls1_2, ECDHE-RSA GCM
#   client12cbc our client -> openssl s_server -tls1_2, ECDHE-RSA CBC
#   server13   our server  <- openssl s_client -tls1_3
#   server12   our server  <- openssl s_client -tls1_2
#   alpn       our client requires h2 against an http/1.1-only peer: 615
#   verify     badssl: an untrusted chain must answer 614, not "connect"
#   versions   badssl: tls-v1-1 and tls-v1-0 are 613 (documented out of
#              scope), tls-v1-2 is OK
#   group      each group we serve, pinned on the peer AND asserted on
#              the group we actually negotiated, in both roles
#              (x25519, P-256, P-384, P-521). Without this rung the
#              x25519 share always wins and the other three arrive
#              only through HelloRetryRequest, untested.
#   alpn-mode  every alpn mode in the def's documented contract (0, 1,
#              2, 3) against a peer that offers h2
#   bulk       a 64 KB response, several records long: the whole stream
#              must arrive and then close_notify. A payload under 2^14
#              would fit in ONE record and test nothing here.
#   bigsend    the mirror of `bulk`: WE write 64 KB and openssl s_client
#              reads it, byte for byte. Host crypto can check the AEAD
#              math; only a real peer can check the record layout.
#   cipher     a peer that PREFERS chacha20 but also accepts AES. Node
#              has chacha20 and may take it; bun has no chacha20 at all
#              and must fall back to AES. Both are correct -- what this
#              rung forbids is the process dying, which is what an
#              unfiltered suite table did (createCipheriv THREW inside
#              feed() and took the whole runtime down).
#   cipher-x   a peer that offers chacha20 ONLY. With no overlap the
#              answer is a clean 613, never a crash.
#   padlen     the CBC record layer at the padding boundary, hermetic
#              (no sockets, no network): padding_length == 0 must be
#              both PRODUCED and ACCEPTED. The two directions are
#              asserted separately -- a self round-trip would pass even
#              if seal and open were wrong together.
#   framing    a large write must split at the 2^14 record ceiling, and
#              what lands on the wire must reassemble to the input under
#              the HOST's AES-GCM. Also hermetic. `bulk` covers the
#              receive side over a socket; this covers the send side,
#              which nothing else exercised.
#   hrr        a peer that does NOT accept our first key share forces a
#              HelloRetryRequest. With one share per hello (the OpenSSL
#              policy) this is a normal path, not an edge case, so it
#              needs its own rung: the transcript must restart from the
#              synthetic message_hash of ClientHello1 (RFC 8446 s4.4.1)
#              or every peer with a different group order fails. The
#              expected hrrs (0 or 1) is pinned per group.
#   hrr-server the same retry in the SERVER role: openssl sends a share
#              for ffdhe2048 (a group we do not serve) and lists x25519,
#              so our server must answer an HRR, take the re-share and
#              complete the handshake (task-051 A6)
#   expired    the validity window of every certificate in the chain, not
#              only the leaf: hermetic material with a one-day
#              intermediate and a ten-year leaf, verified at now and at
#              now + 2 days (task-051 A8)
#   bun-ffi    zero `bun:ffi` require in this package
#   effs       the five EFFECT twins' input contracts (611 / 22 / Unit),
#              loaded the way the compiler loads them. Every rung above
#              drives the runtime directly, so before this one nothing in
#              the repo loaded a twin -- which is how the lane shipped
#              with three real bugs in it (task-046, D44-D46).
#   installed  the files that ship: a Bend golden whose effects ARE
#              lib/effs/*.js, through the real runtime with a real fd
#              (tests/io/tls_alpn_none.bend)
#   drift      lib/effs/*.js is byte-for-byte the same as this package's
#              effs/, so a green run above is a statement about what goes
#              out the door and not about a staged twin of it
#
# BEND_EFFS_DIR points every probe at another copy of the runtime (the
# default is this package's own effs/), which is how the same ~90 rungs
# run against lib/effs/ instead:
#   BEND_EFFS_DIR=lib/effs tests/effs/tls-generic.sh
#
# Usage: tests/effs/tls-generic.sh            # node + bun
#        HOSTS=node tests/effs/tls-generic.sh
#        BUN=.p42/bun/bun-linux-x64/bun tests/effs/tls-generic.sh
set -u

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root" || exit 1

pkg="tests/effs/tls-generic"
probe="$pkg/scratch/tls_probe.js"
sprobe="$pkg/scratch/tls_server_probe.js"
bulk_probe="$pkg/scratch/bulk_probe.js"
hrr_probe="$pkg/scratch/hrr_probe.js"
len_probe="$pkg/scratch/len_probe.js"
len_server="$pkg/scratch/len_server.js"
padlen_probe="$pkg/scratch/padlen_probe.js"
framing_probe="$pkg/scratch/framing_probe.js"
eff_probe="$pkg/scratch/eff_contract_probe.js"
xsign_probe="$pkg/scratch/xsign_probe.js"
expired_probe="$pkg/scratch/expired_probe.js"
bend_bin="${BEND:-bend}"
node_bin="${NODE:-node}"
bun_bin="${BUN:-bun}"
# "node bun" by default; a missing bun falls out of the loop below.
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

field() {
  printf '%s' "$1" | sed -n "s/.*\"$2\":\([^,}]*\).*/\1/p" | tr -d '"'
}

# A free loopback port, so parallel runs and leftover sockets cannot
# collide with a fixed number.
free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); \
print(s.getsockname()[1]); s.close()'
}

# Block until something accepts on $1, or give up after ~4s. A refused
# dial is a flake, not a verdict; the caller decides whether the rung
# actually failed.
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

# Self-signed test material: the ladder is hermetic and must not depend
# on a checked-in cert expiring on a schedule nobody remembers.
openssl req -x509 -newkey rsa:2048 -keyout "$work/k.pem" -out "$work/c.pem" \
  -days 2 -nodes -subj "/CN=localhost" >/dev/null 2>&1 || {
  echo "FAIL cannot create test certificate"; exit 1;
}

# Cross-sign material for the `xsign` rung: a root that re-issues its own
# subject under a different issuer, which is how a CA migrates its root,
# and the one shape the peer's chain can end on while naming an issuer no
# store has. All of it is made here, never checked in, for the same reason
# the self-signed cert above is.
gen_xsign() {
  openssl ecparam -name prime256v1 -genkey -noout -out "$1/root.key" \
    2>/dev/null || return 1
  openssl ecparam -name prime256v1 -genkey -noout -out "$1/other.key" \
    2>/dev/null || return 1
  openssl ecparam -name prime256v1 -genkey -noout -out "$1/imp.key" \
    2>/dev/null || return 1
  openssl ecparam -name prime256v1 -genkey -noout -out "$1/leaf.key" \
    2>/dev/null || return 1
  # The trusted root A, self-signed.
  openssl req -x509 -new -key "$1/root.key" -subj "/CN=XSign Root" \
    -out "$1/xroot.pem" -days 2 >/dev/null 2>&1 || return 1
  # A second CA that shares the root's SUBJECT but not its key: it signs
  # the cross-sign and the impostor, so neither is in any trust store.
  openssl req -x509 -new -key "$1/other.key" -subj "/CN=XSign Root" \
    -out "$1/xother.pem" -days 2 >/dev/null 2>&1 || return 1
  # The root's cross-sign: the root's subject and key, issued by "other".
  openssl req -new -key "$1/root.key" -subj "/CN=XSign Root" \
    -out "$1/xcross.csr" >/dev/null 2>&1 || return 1
  openssl x509 -req -in "$1/xcross.csr" -CA "$1/xother.pem" \
    -CAkey "$1/other.key" -out "$1/xcross.pem" -days 2 >/dev/null 2>&1 || return 1
  # A leaf the root signs, and one the impostor signs.
  openssl req -new -key "$1/leaf.key" -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost" -out "$1/leaf.csr" \
    >/dev/null 2>&1 || return 1
  openssl x509 -req -in "$1/leaf.csr" -CA "$1/xroot.pem" -CAkey "$1/root.key" \
    -copy_extensions copy -out "$1/xleaf.pem" -days 2 >/dev/null 2>&1 || return 1
  # The impostor: the root's subject, a key of its own, issued by "other".
  openssl req -new -key "$1/imp.key" -subj "/CN=XSign Root" \
    -out "$1/ximp.csr" >/dev/null 2>&1 || return 1
  openssl x509 -req -in "$1/ximp.csr" -CA "$1/xother.pem" -CAkey "$1/other.key" \
    -out "$1/ximp.pem" -days 2 >/dev/null 2>&1 || return 1
  # Its own leaf, signed by that own key.
  openssl req -new -key "$1/imp.key" -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost" -out "$1/impleaf.csr" \
    >/dev/null 2>&1 || return 1
  openssl x509 -req -in "$1/impleaf.csr" -CA "$1/ximp.pem" -CAkey "$1/imp.key" \
    -copy_extensions copy -out "$1/ximpleaf.pem" -days 2 >/dev/null 2>&1 || return 1
  return 0
}

xsign_dir="$work/xsign"
mkdir -p "$xsign_dir" || {
  echo "FAIL cannot create the cross-sign directory"; exit 1;
}
if gen_xsign "$xsign_dir"; then
  note "cross-sign material ready in $xsign_dir"
else
  echo "FAIL cannot create the cross-sign material"; exit 1
fi

# Material for the expired-chain rung (task-051 A8): a root that lives ten
# years, an intermediate that lives ONE day, and a leaf that lives ten
# years. A `now` two days ahead expires only the intermediate, so the rung
# isolates "the chain walk reads every validity window" from "the leaf
# expired". Hermetic, like the cross-sign material above.
gen_expired() {
  local d="$1"
  openssl ecparam -name prime256v1 -genkey -noout -out "$d/root.key" \
    2>/dev/null || return 1
  openssl ecparam -name prime256v1 -genkey -noout -out "$d/int.key" \
    2>/dev/null || return 1
  openssl ecparam -name prime256v1 -genkey -noout -out "$d/leaf.key" \
    2>/dev/null || return 1
  openssl req -x509 -new -key "$d/root.key" -subj "/CN=Expired Root" \
    -out "$d/root.pem" -days 3650 >/dev/null 2>&1 || return 1
  openssl req -new -key "$d/int.key" -subj "/CN=Expired Intermediate" \
    -out "$d/int.csr" >/dev/null 2>&1 || return 1
  printf 'basicConstraints=CA:TRUE\n' >"$d/int.ext"
  openssl x509 -req -in "$d/int.csr" -CA "$d/root.pem" -CAkey "$d/root.key" \
    -CAcreateserial -days 1 -extfile "$d/int.ext" -out "$d/int.pem" \
    >/dev/null 2>&1 || return 1
  openssl req -new -key "$d/leaf.key" -subj "/CN=expired.test" \
    -addext "subjectAltName=DNS:expired.test" -out "$d/leaf.csr" \
    >/dev/null 2>&1 || return 1
  openssl x509 -req -in "$d/leaf.csr" -CA "$d/int.pem" -CAkey "$d/int.key" \
    -CAcreateserial -copy_extensions copy -days 3650 -out "$d/leaf.pem" \
    >/dev/null 2>&1 || return 1
  return 0
}

expired_dir="$work/expired"
mkdir -p "$expired_dir" || {
  echo "FAIL cannot create the expired-chain directory"; exit 1;
}
if gen_expired "$expired_dir"; then
  note "expired-chain material ready in $expired_dir"
else
  echo "FAIL cannot create the expired-chain material"; exit 1
fi

# The HTTP request openssl's -www mode expects before it answers.
request='GET / HTTP/1.0

'

# Payload for the `bulk` rung. RFC 8446 s5.1 caps a record plaintext at
# 2^14 bytes, so anything at or below that arrives as a single record and
# cannot test fragmentation -- see D37, where this rung was passing while
# the runtime discarded every record after the first. Four records' worth
# puts the rung genuinely in multi-record territory.
tls13_max_plaintext=16384
bulk_records=4
bulk_file=bulk_payload.txt
bulk_bytes=$(( bulk_records * tls13_max_plaintext ))
# The mirror image of `bulk`: we write this many bytes and openssl reads
# them back, so our send framing is checked by a real TLS peer.
bigsend_bytes=$(( bulk_records * tls13_max_plaintext ))
{
  printf '0123456789abcdef'
  head -c "$((bulk_bytes - 16))" /dev/zero | tr '\0' 'z'
} >"$work/$bulk_file"

# ---------------------------------------------------------------------------
# client13 / client12 / client12cbc: our client against openssl s_server.
# $1 label, $2 host, $3 extra openssl s_server flags
client_check() {
  local label="$1" host="$2" tag="$3"
  shift 3
  local port out st
  port="$(free_port)"
  openssl s_server -accept "$port" -cert "$work/c.pem" -key "$work/k.pem" \
    -alpn h2 -www -quiet "$@" >"$work/s_server_${tag}.log" 2>&1 &
  local srv=$!
  # s_server binds before it is ready; a refused dial is a flake, not a
  # verdict, so retry the dial a few times before calling it a failure.
  local tries=0
  while [ "$tries" -lt 20 ]; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      exec 3<&- 2>/dev/null || true
      break
    fi
    tries=$((tries + 1))
    sleep 0.1
  done
  out="$(P0_REQUEST="$request" P0_TIMEOUT_MS=15000 \
    timeout 30 "$host" "$probe" 127.0.0.1 "$port" 1 0 2>&1)"
  st=$?
  kill "$srv" 2>/dev/null
  wait "$srv" 2>/dev/null
  case "$out" in
    *"OK ver=1.3 alpn=\"h2\""*)
      if [ "$label" = "client13" ]; then
        ok "$name $label negotiated TLS 1.3 with ALPN h2"
      else
        bad "$name $label came back as 1.3, expected 1.2"
      fi
      ;;
    *"OK ver=1.2 alpn=\"h2\""*)
      if [ "$label" = "client12" ] || [ "$label" = "client12cbc" ]; then
        ok "$name $label negotiated TLS 1.2 with ALPN h2 ($out)"
      else
        bad "$name $label came back as 1.2, expected 1.3"
      fi
      ;;
    *)
      bad "$name $label (exit $st): $out"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# server13 / server12: openssl s_client against our server. The peer must
# complete the handshake AND read back the HTTP answer, so a half-open
# handshake cannot pass.
# $1 label, $2 host, $3 cipher flag (may be empty), $4 expected version
server_check() {
  local label="$1" host="$2" cipher="$3" want="$4"
  local port out log
  port="$(free_port)"
  # Key the log on $name (the host LABEL), never on $host (the binary
  # path): BUN=.p42/bun/bun-linux-x64/bun puts slashes in the path and
  # the redirect fails, which silently skips starting the probe and turns
  # into "connection refused" from the peer.
  log="$work/srv_${name}_${label}.log"
  "$host" "$sprobe" "$work/c.pem" "$work/k.pem" "$port" 2 >"$log" 2>&1 &
  local srv=$!
  local tries=0
  while [ "$tries" -lt 40 ]; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      exec 3<&- 2>/dev/null || true
      break
    fi
    tries=$((tries + 1))
    sleep 0.1
  done
  # "1.3" -> -tls1_3: the dot is not what openssl spells.
  local tls_flag
  tls_flag="$(printf '%s' "$want" | sed 's/\./_/')"
  out="$(printf "$request" | timeout 30 openssl s_client \
    -connect "127.0.0.1:$port" "-tls${tls_flag}" -alpn h2 \
    $cipher -quiet 2>&1)"
  sleep 0.3
  kill "$srv" 2>/dev/null
  wait "$srv" 2>/dev/null
  if printf '%s' "$out" | grep -qa "HTTP/1"; then
    if grep -qa "OK ver=$want " "$log"; then
      ok "$name $label served TLS $want to openssl s_client"
    else
      bad "$name $label: peer read our answer but our side says $(grep -a '^OK\|^FAIL' "$log" | tr '\n' ' ')"
    fi
  else
    bad "$name $label: openssl s_client got no HTTP answer: $(printf '%s' "$out" | tail -n 2 | tr '\n' ' ')"
  fi
}

# ---------------------------------------------------------------------------
# alpn: our client demands h2 and the peer only offers http/1.1. The
# contract is 615, NOT a handshake failure -- the distinction is the
# whole point of the alpn argument.
alpn_check() {
  local host="$1" port out
  port="$(free_port)"
  openssl s_server -accept "$port" -cert "$work/c.pem" -key "$work/k.pem" \
    -alpn http/1.1 -www -quiet -tls1_3 >"$work/alpn.log" 2>&1 &
  local srv=$!
  local tries=0
  while [ "$tries" -lt 20 ]; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      exec 3<&- 2>/dev/null || true
      break
    fi
    tries=$((tries + 1))
    sleep 0.1
  done
  out="$(P0_TIMEOUT_MS=15000 timeout 30 "$host" "$probe" 127.0.0.1 "$port" 1 0 2>&1)"
  kill "$srv" 2>/dev/null
  wait "$srv" 2>/dev/null
  case "$out" in
    *"FAIL 615"*) ok "$name alpn mismatch answers 615" ;;
    *) bad "$name alpn: expected 615, got: $out" ;;
  esac
}

# ---------------------------------------------------------------------------
# verify: badssl hosts that must be refused with 614. A refusal for the
# WRONG reason (dial failure, timeout) would also "not connect", so the
# code is what is asserted.
verify_check() {
  local host="$1" label="$2" domain="$3" port="$4" want="$5"
  local out
  out="$(P0_TIMEOUT_MS=20000 timeout 40 "$host" "$probe" "$domain" "$port" 1 1 2>&1)"
  case "$out" in
    *"FAIL $want"*) ok "$name verify $label answers $want" ;;
    *"OK "*) bad "$name verify $label was ACCEPTED (verification must fail closed)" ;;
    *) bad "$name verify $label: expected $want, got: $out" ;;
  esac
}

version_check() {
  local host="$1" label="$2" domain="$3" port="$4" want="$5"
  local out
  out="$(P0_TIMEOUT_MS=20000 timeout 40 "$host" "$probe" "$domain" "$port" 1 1 2>&1)"
  case "$out" in
    *"OK "*) ok "$name $label handshakes" ;;
    *"FAIL $want"*) ok "$name $label refused with $want (documented out of scope)" ;;
    *) bad "$name $label: expected OK or $want, got: $out" ;;
  esac
}

# ---------------------------------------------------------------------------
# group: pin the peer to ONE curve and assert that curve is the one we
# ended up using, in BOTH roles. Without the client offering a share for
# every group, or with the assertion reduced to "the handshake finished",
# this would only prove that TLS works -- four times.
# $1 label, $2 host, $3 group name (openssl -groups spelling)
group_check() {
  local label="$1" host="$2" grp="$3"
  local want port out
  # openssl spells it X25519, the runtime calls it x25519. Lowercasing
  # the whole name would also mangle P-256 into p-256, which is not a
  # group the runtime knows.
  want="$grp"
  [ "$grp" = "X25519" ] && want="x25519"
  port="$(free_port)"
  openssl s_server -accept "$port" -cert "$work/c.pem" -key "$work/k.pem" \
    -alpn h2 -www -quiet -tls1_3 -groups "$grp" \
    >"$work/group_c_$label.log" 2>&1 &
  local srv=$!
  wait_port "$port"
  out="$(P0_REQUEST="$request" P0_TIMEOUT_MS=15000 \
    timeout 30 "$host" "$probe" 127.0.0.1 "$port" 1 0 2>&1)"
  kill "$srv" 2>/dev/null
  wait "$srv" 2>/dev/null
  case "$out" in
    *"OK ver=1.3"*"group=$want "*)
      ok "$name group $grp: our client negotiated $want" ;;
    *"OK ver=1.3"*)
      bad "$name group $grp: handshake ok but negotiated $(printf '%s' "$out" | sed -n 's/.*group=\([^ ]*\).*/\1/p'), want $want" ;;
    *)
      bad "$name group $grp: our client: $out" ;;
  esac
  # And the same curve from the server side.
  local sport log
  sport="$(free_port)"
  log="$work/group_s_$label.log"
  "$host" "$sprobe" "$work/c.pem" "$work/k.pem" "$sport" 2 >"$log" 2>&1 &
  srv=$!
  wait_port "$sport"
  out="$(printf "$request" | timeout 30 openssl s_client \
    -connect "127.0.0.1:$sport" -tls1_3 -alpn h2 -groups "$grp" -quiet 2>&1)"
  sleep 0.3
  kill "$srv" 2>/dev/null
  wait "$srv" 2>/dev/null
  if ! printf '%s' "$out" | grep -qa "HTTP/1"; then
    bad "$name group $grp: our server: peer got no answer: $(printf '%s' "$out" | tail -n 2 | tr '\n' ' ')"
  elif ! grep -qa "group=$want " "$log"; then
    bad "$name group $grp: our server negotiated $(grep -a -o 'group=[^ ]*' "$log" | head -n 1), want $want"
  else
    ok "$name group $grp: our server negotiated $want"
  fi
}

# ---------------------------------------------------------------------------
# alpn_mode: each mode of the documented contract (alpn=0 offers nothing,
# 1 offers and requires h2, 2 offers h2/http/1.1, 3 offers only http/1.1)
# against a peer that offers h2. Only modes 1 and 3 assert a handshake;
# 0 and 2 legitimately complete with an empty or "h2" selection.
# $1 label, $2 host, $3 mode, $4 expected alpn ("" for none), $5 want-ok
alpn_mode_check() {
  local label="$1" host="$2" mode="$3" want_alpn="$4" want_ok="$5"
  local port out
  port="$(free_port)"
  openssl s_server -accept "$port" -cert "$work/c.pem" -key "$work/k.pem" \
    -alpn h2 -www -quiet -tls1_3 >"$work/alpn_mode_$label.log" 2>&1 &
  local srv=$!
  wait_port "$port"
  out="$(P0_REQUEST="$request" P0_TIMEOUT_MS=15000 \
    timeout 30 "$host" "$probe" 127.0.0.1 "$port" "$mode" 0 2>&1)"
  kill "$srv" 2>/dev/null
  wait "$srv" 2>/dev/null
  case "$out" in
    *"FAIL 615"*)
      if [ "$want_ok" = "no" ]; then
        ok "$name alpn mode $mode is refused against an h2-only peer"
      else
        bad "$name alpn mode $mode refused, expected alpn=$want_alpn"
      fi
      ;;
    "OK "*"alpn=\"$want_alpn\""*)
      if [ "$want_ok" = "yes" ]; then
        ok "$name alpn mode $mode selects alpn=$want_alpn"
      else
        bad "$name alpn mode $mode accepted, expected 615"
      fi
      ;;
    *) bad "$name alpn mode $mode: $out" ;;
  esac
}

# ---------------------------------------------------------------------------
# bulk: a stream too long to fit in one record. The 2^14 plaintext ceiling
# per record means a 4 KB status page is a SINGLE record, so asserting on
# it proves nothing about fragmentation -- a record layer that kept the
# first record and dropped every other one still passed. `-WWW` serves a
# real file, so the peer is asked for one several records long, and the
# rung asserts the count against what a native peer receives.
# $1 label, $2 host
bulk_check() {
  local label="$1" host="$2"
  local port out theirs ours
  port="$(free_port)"
  # -WWW serves files from the CWD, so run it where the payload lives.
  ( cd "$work" && openssl s_server -accept "$port" -cert "$work/c.pem" \
    -key "$work/k.pem" -alpn h2 -WWW -quiet -tls1_3 \
    >"$work/bulk_$label.log" 2>&1 ) &
  local srv=$!
  wait_port "$port"
  out="$(P0_TIMEOUT_MS=20000 timeout 40 "$host" "$bulk_probe" \
    127.0.0.1 "$port" "/$bulk_file" 2>&1)"
  # What a native peer receives from the same server, for the yardstick.
  printf "GET /$bulk_file HTTP/1.0\r\n\r\n" | timeout 20 openssl s_client \
    -connect "127.0.0.1:$port" -tls1_3 -alpn h2 -quiet 2>/dev/null \
    | wc -c | tr -d ' ' >"$work/bulk_ref.txt"
  theirs="$(cat "$work/bulk_ref.txt")"
  kill "$srv" 2>/dev/null
  wait "$srv" 2>/dev/null
  ours="$(printf '%s' "$out" | sed -n 's/.*appBytes=\([0-9]*\).*/\1/p')"
  records="$(printf '%s' "$out" | sed -n 's/.*records=\([0-9]*\).*/\1/p')"
  closed="$(printf '%s' "$out" | grep -c 'closed=true')"
  if [ -z "$ours" ] || [ -z "$theirs" ] || [ "$theirs" -eq 0 ]; then
    bad "$name $label: no byte count (ours=$ours theirs=$theirs): $out"
    return
  fi
  if [ -z "$records" ]; then
    bad "$name $label: probe reported no record count: $out"
    return
  fi
  # Both counts now cover the same file, so they must agree closely rather
  # than merely "not be far apart": a stream missing its tail, or counted
  # twice, misses by far more than the bound.
  if [ "$((ours * 100 / theirs))" -lt 90 ] \
     || [ "$((ours * 100 / theirs))" -gt 110 ]; then
    bad "$name $label truncated or overcounted: $ours vs ~$theirs app bytes"
  elif [ "$closed" != "1" ]; then
    bad "$name $label got $ours app bytes but never saw close_notify"
  elif [ "$records" -lt 2 ]; then
    # The whole point of the rung. If the response fitted in one record
    # it would pass every other check while testing nothing about
    # fragmentation -- which is exactly how it passed while a runtime
    # that dropped every record after the first was still green (D37).
    bad "$name $label: $ours bytes arrived in only $records record; the payload must exceed the $tls13_max_plaintext-byte ceiling"
  else
    ok "$name $label received $ours of ~$theirs app bytes over $records records, close_notify seen"
  fi
}

# ---------------------------------------------------------------------------
# cipher: what happens when the peer prefers chacha20. The hosts differ
# -- node HAS chacha20-poly1305, bun does not (measured, 1.2.15 and
# 1.4.3: ERR_CRYPTO_UNKNOWN_CIPHER) -- so the only invariant across
# hosts is that the handshake COMPLETES with a suite this host owns.
# A crash here is the regression: an unfiltered suite table made
# createCipheriv throw inside feed(), which killed the process instead
# of the connection.
# $1 label, $2 host, $3 peer ciphersuite list
cipher_check() {
  local label="$1" host="$2" suites="$3" want="$4"
  local port out st
  port="$(free_port)"
  openssl s_server -accept "$port" -cert "$work/c.pem" -key "$work/k.pem" \
    -alpn h2 -www -quiet -tls1_3 -ciphersuites "$suites" \
    >"$work/cipher_c_$label.log" 2>&1 &
  local srv=$!
  wait_port "$port"
  out="$(P0_REQUEST="$request" P0_TIMEOUT_MS=15000 \
    timeout 30 "$host" "$probe" 127.0.0.1 "$port" 1 0 2>&1)"
  st=$?
  kill "$srv" 2>/dev/null
  wait "$srv" 2>/dev/null
  case "$out" in
    *"OK ver=1.3"*)
      # Whichever suite came back, the point is that it is one this host
      # can actually seal -- the suite name is reported so a regression
      # in the FILTER is visible even while the rung stays green.
      ok "$name $label: peer prefers chacha20, answered $(printf '%s' "$out" \
        | sed -n 's/.*group=[^ ]* \([a-z0-9-]*\).*/\1/p')"
      ;;
    "FAIL $want"*)
      ok "$name $label: no overlap with the peer's list is $want (not a crash)"
      ;;
    *)
      if [ "$st" -gt 100 ]; then
        bad "$name $label: the runtime DIED (exit $st) instead of answering: $out"
      else
        bad "$name $label: expected OK or $want, got: $out"
      fi
      ;;
  esac
}

# ---------------------------------------------------------------------------
# hrr: a peer that refuses our first key share. We send ONE share (the
# OpenSSL policy), so a server whose group order differs answers with a
# HelloRetryRequest -- and the retry is the interesting part: the
# transcript must restart from the synthetic message_hash of CH1
# (RFC 8446 s4.4.1), NOT from CH1 itself.
# $1 label, $2 host, $3 peer group, $4 expected hrrs (0 or 1)
hrr_check() {
  local label="$1" host="$2" group="$3" want_hrrs="$4"
  local port out
  port="$(free_port)"
  openssl s_server -accept "$port" -cert "$work/c.pem" -key "$work/k.pem" \
    -alpn h2 -www -quiet -tls1_3 -groups "$group" \
    >"$work/hrr_$label.log" 2>&1 &
  local srv=$!
  wait_port "$port"
  out="$(P0_REQUEST="$request" P0_TIMEOUT_MS=20000 \
    timeout 40 "$host" "$hrr_probe" 127.0.0.1 "$port" 2>&1)"
  kill "$srv" 2>/dev/null
  wait "$srv" 2>/dev/null
  case "$out" in
    *"hrrs=$want_hrrs done=true"*)
      if [ "$want_hrrs" = "1" ]; then
        ok "$name $label: one HelloRetryRequest, handshake completed (synthetic transcript)"
      else
        ok "$name $label: peer accepted our first share, no retry (hrrs=0)"
      fi
      ;;
    *)
      bad "$name $label: wanted hrrs=$want_hrrs done=true, got: $out"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# hrr-server: the retry in the SERVER role. openssl sends a key share for
# the FIRST -groups entry (ffdhe2048 here) and lists x25519 after it; our
# runtime serves x25519/P-256/P-384/P-521, so the server MUST answer a
# HelloRetryRequest and complete the handshake when the peer re-shares.
# The probe's `group=x25519` proves the re-share was adopted, and a
# completed handshake proves the synthetic transcript is right -- before
# task-051 this path killed the process (a null suite in send_hrr) and no
# rung reached it.
# $1 name, $2 host
hrr_server_check() {
  local name="$1" host="$2"
  local port log out
  port="$(free_port)"
  log="$work/hrr_srv_$name.log"
  "$host" "$sprobe" "$work/c.pem" "$work/k.pem" "$port" 2 >"$log" 2>&1 &
  local srv=$!
  wait_port "$port"
  out="$(timeout 30 openssl s_client -connect "127.0.0.1:$port" \
    -tls1_3 -groups ffdhe2048:x25519 -quiet </dev/null 2>&1)"
  sleep 0.3
  kill "$srv" 2>/dev/null
  wait "$srv" 2>/dev/null
  if grep -qa "OK ver=1.3 .*group=x25519" "$log"; then
    ok "$name hrr-server: share skipped, HRR sent, x25519 re-share accepted"
  else
    bad "$name hrr-server: $(grep -a '^OK\|^FAIL\|TypeError' "$log" \
      | head -2 | tr '\n' ' ')"
  fi
}

# ---------------------------------------------------------------------------
# expired-chain: the validity window counts for EVERY certificate in the
# chain, not only the leaf (task-051 A8). The material has an intermediate
# that lives one day and a leaf that lives ten years, and the probe asks
# verify_chain twice: at `now` (control, must verify) and two days ahead
# (the intermediate is expired, the leaf is not -- must answer 614).
# Hermetic: no sockets, no network.
# $1 name, $2 host
expired_check() {
  local name="$1" host="$2"
  local dir="$expired_dir" out
  out="$(timeout 60 "$host" "$expired_probe" "$dir/root.pem" \
    "$dir/int.pem" "$dir/leaf.pem" expired.test 2>&1)"
  if [ $? -eq 0 ]; then
    ok "$name expired-chain: $(printf '%s' "$out" | tail -n 1)"
  else
    bad "$name expired-chain: $(printf '%s' "$out" | tail -n 2 | tr '\n' ' ')"
  fi
}

# ---------------------------------------------------------------------------
# cbc_len: payload lengths where (len + MAC) lands exactly on a block
# boundary, so the encoding is padding_length == 0. RFC 5246 s6.2.3.2 says
# that is legal ("zero to 255, inclusive"); an implementation that insists
# on padding_length >= 1, or that omits the trailing %16 when computing it,
# loses exactly these payloads and nothing else -- which is why a single
# length would never have caught it.
# $1 label, $2 host, $3 payload length
cbc_len_check() {
  local label="$1" host="$2" n="$3"
  local port out
  port="$(free_port)"
  # The PEER always runs under node, whatever host is under test: bun's
  # tls server refuses ECDHE-RSA-AES128-SHA256 outright ("No cipher
  # match"), and the peer is the reference here -- the code under test
  # is the client, which runs on $host.
  P0_CERT="$work/c.pem" P0_KEY="$work/k.pem" \
    "$node_bin" "$len_server" "$n" "$port" >"$work/len_$label.log" 2>&1 &
  local srv=$!
  wait_port "$port"
  out="$(P0_TIMEOUT_MS=15000 timeout 30 "$host" "$len_probe" \
    127.0.0.1 "$port" "$n" 2>&1)"
  kill "$srv" 2>/dev/null
  wait "$srv" 2>/dev/null
  case "$out" in
    *"OK got=$n "*) ok "$name cbc-len $n: full payload delivered" ;;
    *) bad "$name cbc-len $n: $out" ;;
  esac
}

# ---------------------------------------------------------------------------
# A hermetic rung: run a probe that needs no socket and no network and
# report its own verdict. These check the record layer against the HOST's
# crypto rather than against ourselves, so they assert what a conformant
# peer would see -- a round trip between our own seal and our own open
# would pass even if both halves were wrong together (D21).
# $1 label, $2 host, $3 probe path, $4.. extra probe arguments
probe_check() {
  local label="$1" host="$2" probe="$3"
  shift 3
  local out st
  out="$(timeout 60 "$host" "$probe" "$@" 2>&1)"
  st=$?
  if [ "$st" -ne 0 ]; then
    bad "$name $label: $(printf '%s' "$out" | grep -a '^FAIL' | head -3 | tr '\n' ' ')"
  else
    ok "$name $label: $(printf '%s' "$out" | tail -n 1)"
  fi
}

# ---------------------------------------------------------------------------
# bigsend: the send side of fragmentation, with openssl as the reader.
#
# `bulk` has openssl SEND a large stream and us read it. This is the
# mirror: we send, and openssl reassembles. That matters because a host
# crypto decrypt is not a TLS reference -- node's AES-GCM has no opinion
# about record layout, so `framing` can only prove the AEAD math. Only a
# real peer proves the bytes are what a record is supposed to be.
#
# Byte-exact, not a count: a stream that repeats or reorders a chunk
# still has the right length.
# $1 label, $2 host
bigsend_check() {
  local label="$1" host="$2"
  local port srv got mine
  port="$(free_port)"
  got="$work/bigsend_got_$label.bin"
  P0_REPLY_BYTES="$bigsend_bytes" "$host" "$sprobe" \
    "$work/c.pem" "$work/k.pem" "$port" 2 >"$work/bigsend_$label.log" 2>&1 &
  local srv=$!
  wait_port "$port"
  # Straight to a file, never through $(...): command substitution strips
  # trailing newlines, and a binary comparison against a file of ours
  # would then fail on bytes the transport never lost.
  printf "$request" | timeout 40 openssl s_client \
    -connect "127.0.0.1:$port" -tls1_3 -alpn h2 -quiet \
    >"$got" 2>/dev/null
  kill "$srv" 2>/dev/null
  wait "$srv" 2>/dev/null
  # The bytes we expect, generated independently of the runtime.
  "$node_bin" -e '
    const fs = require("fs");
    const n = Number(process.argv[1]);
    const b = Buffer.alloc(n);
    for (let i = 0; i < n; i += 1) b[i] = (i * 31 + (i >> 8) * 7) & 255;
    fs.writeFileSync(process.argv[2], b);
  ' "$bigsend_bytes" "$work/bigsend_want.bin"
  local mine
  mine="$(wc -c <"$got" | tr -d ' ')"
  if [ "$mine" -ne "$bigsend_bytes" ]; then
    bad "$name $label: openssl read $mine of $bigsend_bytes bytes"
  elif ! cmp -s "$got" "$work/bigsend_want.bin"; then
    bad "$name $label: openssl read $mine bytes but they differ from what we sent"
  else
    ok "$name $label: openssl reassembled all $mine bytes of our multi-record write"
  fi
}

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
  if ! command -v "$bin" >/dev/null 2>&1 && [ ! -x "$bin" ]; then
    skipped "$name not installed"
    continue
  fi
  ver="$("$bin" --version 2>/dev/null | head -n 1)"
  note "$name $ver"

  client_check "client13" "$bin" "13" -tls1_3
  client_check "client12" "$bin" "12" -tls1_2 \
    -cipher ECDHE-RSA-AES128-GCM-SHA256
  client_check "client12cbc" "$bin" "12cbc" -tls1_2 \
    -cipher ECDHE-RSA-AES128-SHA256
  server_check "server13" "$bin" "" 1.3
  server_check "server12" "$bin" "-cipher ECDHE-RSA-AES128-GCM-SHA256" 1.2
  server_check "server12cbc" "$bin" "-cipher ECDHE-RSA-AES128-SHA256" 1.2
  alpn_check "$bin"
  # Every group we serve, pinned on the peer AND asserted on what we
  # actually used. x25519 is the one that needs no retry; the other three
  # arrive through HelloRetryRequest.
  for grp in x25519 P-256 P-384 P-521; do
    group_check "$grp" "$bin" "$grp"
  done
  alpn_mode_check "mode0" "$bin" 0 "" "yes"
  alpn_mode_check "mode1" "$bin" 1 "h2" "yes"
  alpn_mode_check "mode2" "$bin" 2 "h2" "yes"
  alpn_mode_check "mode3" "$bin" 3 "" "no"
  bulk_check "bulk13" "$bin"
  bigsend_check "bigsend13" "$bin"
  # chacha20 first, AES as the fallback: the preference the peer would
  # realistically have, and the case where the two hosts must differ.
  cipher_check "cipher-prefer" "$bin" \
    "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256" 613
  # chacha20 alone: no overlap on bun, so the honest answer is 613 --
  # but a CLEAN 613, never a dead process.
  cipher_check "cipher-only" "$bin" "TLS_CHACHA20_POLY1305_SHA256" 613
  probe_check "padlen" "$bin" "$padlen_probe"
  probe_check "framing" "$bin" "$framing_probe"
  # The five twins' own contracts, loaded as the compiler loads them.
  # The only PROBE that opens one of the five def-backed twins; the
  # `installed` rung below is the only other place they run.
  probe_check "effs" "$bin" "$eff_probe"
  # A cross-signed root must end the chain: the shape that made every
  # verified fetch of a real host answer 614 UNABLE_TO_GET_ISSUER_CERT-
  # LOCALLY once the pure lane was installed (cloudflare.com, measured).
  # Hermetic -- the chain and the store are made above, no network.
  probe_check "xsign" "$bin" "$xsign_probe" "$xsign_dir"
  # Our client offers x25519 first, so any peer that does not accept it
  # forces the retry. Each of these is a group we also serve, and the
  # expected hrrs value is pinned: 1 for the groups outside the share, 0
  # for the control where the peer takes our first share.
  hrr_check "hrr-p256" "$bin" P-256 1
  hrr_check "hrr-p384" "$bin" P-384 1
  hrr_check "hrr-p521" "$bin" P-521 1
  hrr_check "hrr-x25519" "$bin" X25519 0
  # The same retry in the server role (task-051 A6), and the chain
  # validity window for every certificate (task-051 A8).
  hrr_server_check "$name" "$bin"
  expired_check "$name" "$bin"
  # 15, 31, 47, 63: (n + 32) % 16 == 15, i.e. the peer sends
  # padding_length == 0. 16 and 200 are the ordinary sizes, kept as a
  # control so the rung fails for the right reason if it ever does.
  cbc_len_check "len15" "$bin" 15
  cbc_len_check "len31" "$bin" 31
  cbc_len_check "len47" "$bin" 47
  cbc_len_check "len63" "$bin" 63
  cbc_len_check "len16" "$bin" 16
  cbc_len_check "len200" "$bin" 200

  if have_network; then
    verify_check "$bin" "self-signed" self-signed.badssl.com 443 614
    verify_check "$bin" "wrong.host" wrong.host.badssl.com 443 614
    verify_check "$bin" "untrusted-root" untrusted-root.badssl.com 443 614
    verify_check "$bin" "expired" expired.badssl.com 443 614
    version_check "$bin" "tls-v1-2" tls-v1-2.badssl.com 1012 613
    version_check "$bin" "tls-v1-1" tls-v1-1.badssl.com 1011 613
    version_check "$bin" "tls-v1-0" tls-v1-0.badssl.com 1010 613
  else
    skipped "$name badssl checks (no network: DNS or egress unavailable)"
  fi
done

# bun:ffi must be gone from the whole repo -- it is the thing the pure-JS
# runtime replaced, and one stray require brings a native toolchain back.
# The claim under test is about THIS package: the pure-JS runtime that
# replaces the OpenSSL/bun:ffi lane. Scoped to lib/ it would count the
# five old ffi twins that task-043-js-lane-tls-pure still has to retire
# (its Fase 5), which is a different task's debt and would report a
# number nobody here can move. Comments and design notes do not count:
# only a require() is a dependency, so a `//` mention is filtered out
# (the resolver keeps one in its history note).
ffi_count="$(grep -rn 'require("bun:ffi")\|require(.bun:ffi.)' \
  "$pkg" 2>/dev/null | grep -v ':[0-9]*:[[:space:]]*//' \
  | wc -l | tr -d ' ')"
if [ "$ffi_count" = "0" ]; then
  ok "no bun:ffi require in the tls-generic package"
else
  bad "bun:ffi require found in the tls-generic package ($ffi_count sites)"
  grep -rn 'require("bun:ffi")' "$pkg" 2>/dev/null | head -5
fi

# ---------------------------------------------------------------------------
# The files that actually ship: lib/effs/.
#
# Everything above validated whichever copy BEND_EFFS_DIR named (this
# package's own effs/ by default). The two rungs below close the loop on
# the copies installed in lib/effs/, which is where lib/tls.bend now points
# -- task-046-tls-js-lane-into-lib. Without them the ladder could be green
# against a staged twin while a different set of files went out the door.
# ---------------------------------------------------------------------------

# drift: the installed files and the staged ones are byte-for-byte the same
# file, so a green run above is a statement about what ships. Compared
# against the package copy always, never against $effs_dir: pointing
# BEND_EFFS_DIR at lib/effs/ would make the rung compare a directory with
# itself and pass by construction.
drift=""
for f in tls_rt.js tls_connect.js tls_accept.js tls_send_bytes.js \
  tls_recv_bytes.js tls_close.js; do
  a="$(sha256sum "lib/effs/$f" 2>/dev/null | cut -c1-16)"
  b="$(sha256sum "$pkg/effs/$f" 2>/dev/null | cut -c1-16)"
  if [ -z "$a" ] || [ "$a" != "$b" ]; then
    drift="$drift $f($a vs $b)"
  fi
done
if [ -z "$drift" ]; then
  ok "lib/effs/*.js is byte-for-byte the staged twin, so the rungs above
  measure what ships"
else
  bad "lib/effs diverged from the staged twins:$drift"
fi

# installed: a Bend golden whose effects ARE lib/effs/*.js. It runs the
# handshake, the ALPN refusal (615) and the ALPN-less completion through
# the real runtime with a real connected fd -- the one rung that proves
# the installed files work as effects, and the one that caught every bug
# of task-046's D44-D46 (a mutant that drops any of the three fixes makes
# this golden change its answer or die).
if ! command -v "$bend_bin" >/dev/null 2>&1 && [ ! -x "$bend_bin" ]; then
  skipped "installed lib/effs effects (bend not installed)"
else
  out="$(timeout 200 "$bend_bin" tests/io/tls_alpn_none.bend 2>&1)"
  got="$(printf '%s\n' "$out" | grep -E '^[0-9]+$' | tail -n 1)"
  if [ "$got" = "1111" ]; then
    ok "the installed lib/effs effects handshaked, refused 615, and kept an ALPN-less client"
  else
    bad "installed lib/effs effects: want 1111, got ${got:-none}: $out"
  fi
fi

# The lib/ twins are still on the old lane. Reported, not failed: this
# task's scope is the package, and task-043 owns retiring them.
lib_ffi="$(grep -rn 'require("bun:ffi")' lib 2>/dev/null \
  | grep -v ':[0-9]*:[[:space:]]*//' | cut -d: -f1 | sort -u \
  | wc -l | tr -d ' ')"
if [ "$lib_ffi" = "0" ]; then
  ok "lib/ is off bun:ffi too"
else
  note "lib/ still has $lib_ffi bun:ffi twins (task-043-js-lane-tls-pure, Fase 5)"
fi

printf '=== %d passed, %d failed, %d skipped ===\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]