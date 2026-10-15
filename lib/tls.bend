# TLS over TCP: package-local byte effects with two wire
# implementations below the one contract (no Base patch). The public
# lane is tls_connect / tls_connect_insecure plus the server accept and
# the byte send/recv/close twins of lib/tcp.bend.
#
# The C twins (tls_*.c) ride OpenSSL via dlopen for the native binary
# target; the JS twins ride lib/effs/tls_rt.js -- TLS 1.3 + 1.2 in pure
# JS over the host's crypto builtins, parked on WANT_READ/WANT_WRITE --
# loaded by the cwd-absolute require in the four twins that need the
# record layer (the fifth, tls_close, rides only the handle).
# How the lanes were built and why: docs/tls-dns.md.
#
# The TLS socket handle is opaque — an SSL session box on the C lane, a
# pump box {pump, fd} on the JS lane — never a raw fd: it must ONLY
# ride TLS.send/recv/close, never Base TCP or Socket.close (which would
# orphan the session). Every effect hands the socket back beside its
# Result, like TCP.send_bytes does.
#
# Transport invariant (since 2026-10-13, task-047): the dial is
# Base.TCP.connect's. tls_connect_raw receives an already-connected fd
# — a real fd in op.args[0], what io_park_on wakes on — and only
# handshakes it; the C twin needs the fd blocking for the handshake and
# restores O_NONBLOCK on the success path (every failure path closes
# the fd instead), the JS twin parks. DNS.resolve
# answers the IPv4 the connect rides; the ORIGINAL host rides SNI and
# (later) the :authority/Host header, so virtual hosting never changes.
#
# Fail codes are stable numbers, never OpenSSL/host text: 611 bad input
# (port/fd/ALPN shape; the C twin also rejects a NUL host), 612 dial
# failed — the transport's since
# the dial left the effect, kept as a family number — 613 handshake
# failed, 614 verify failed, 615 ALPN mismatch (client and server roles in
# both lanes: a peer whose offered list has no overlap gets the fatal
# no_application_protocol alert on either lane, and the effects classify
# it by the reason code -- 235 when we refused, 1120 when we received the
# alert), 616 TLS error.
# DNS failures keep their 601-605 codes and surface before any socket
# exists, so no handle can leak.
#
# Import as: import ./tls.bend as TLS (from lib) or
# import ../../lib/tls.bend as TLS (from tests/io).
# Then TLS.tls_connect, TLS.tls_connect_insecure, TLS.tls_connect_noalpn,
# TLS.tls_connect_noalpn_insecure, TLS.tls_connect_any,
# TLS.tls_connect_any_insecure, TLS.tls_accept, TLS.tls_accept_alpn,
# TLS.tls_accept_http1, TLS.tls_send_bytes, TLS.tls_recv_bytes,
# TLS.tls_close.
import Base
import ./dns.bend as DNS

# The raw client handshake over an already-connected fd: Base.TCP.connect
# does the dial (so the fd keeps the non-blocking mode it was born with)
# and this def only handshakes. The C twin (OpenSSL) makes the fd
# blocking for the handshake and restores O_NONBLOCK on both exits; the
# JS twin (tls_rt.js) parks on WANT_READ / WANT_WRITE instead. SNI rides
# sni, the chain is verified iff verify is 1, and the ALPN mode is
# alpn=1 offers h2 and requires the selection to be h2 (anything else is
# 615), 2 offers h2+http/1.1, 3 offers only http/1.1, 0 offers nothing.
# Answers the session box and the selected protocol on Done.
#
# The first parameter is the socket, not the host: that is what puts a
# real fd in op.args[0], the only thing io_park_on can wake on. The other
# four defs take their handle the same way.
def tls_connect_raw(sock: Socket, sni: String, verify: U32, alpn: U32) ->
  IO(Result<&1, &1, U32 & String, Socket & String>):
  import "./effs/tls_connect.c"
  import "./effs/tls_connect.js"

# The raw server handshake returns the selected ALPN protocol beside the
# socket. offer=1 picks h2 when the peer offers it; offer=2 picks h2 or
# http/1.1; offer=3 picks http/1.1 only. A peer that offers NO ALPN is
# not a mismatch: the extension is simply not used (RFC 7301 s3.2) and
# the handshake completes with an empty protocol -- what every WSS client
# does on purpose. A peer whose offered list has no overlap is refused
# 615 on both lanes, after the fatal no_application_protocol alert (120)
# the RFC requires. Callers that need h2 must check the returned string.
def tls_accept_raw(listener: Listener, cert: String, key: String, offer: U32) ->
  IO(Listener & Result<&1, &1, U32 & String, Socket & String>):
  import "./effs/tls_accept.c"
  import "./effs/tls_accept.js"

def tls_valid_port(+p: U32) -> Bool:
  Bool.and(U32.is_ge(p, 1), U32.is_le(p, 65535))

def tls_connect.without_alpn(
  r: Result<&1, &1, U32 & String, Socket & String>) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  match r:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, Socket>, Fail{e})
    case Done{value}:
      (sock, protocol) = value
      IO.pure(Result<&1, &1, U32 & String, Socket>, Done{sock})

def tls_dial_any.dialed(+host: String, +verify: U32,
  r: Result<&1, &1, U32 & String, Socket>) ->
  IO(Result<&1, &1, U32 & String, Socket & String>):
  match r:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, Socket & String>, Fail{e})
    case Done{sock}:
      tls_connect_raw(sock, host, verify, 2)

def tls_dial_any.asked(+port: U32, +verify: U32, +host: String,
  r: Result<&1, &1, U32 & String, String>) ->
  IO(Result<&1, &1, U32 & String, Socket & String>):
  match r:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, Socket & String>, Fail{e})
    case Done{ip}:
      do IO<Result<&1, &1, U32 & String, Socket & String>>:
        d : Result<&1, &1, U32 & String, Socket> <- TCP.connect(ip, port)
        tls_dial_any.dialed(host, verify, d)

def tls_dial_any(+host: String, port: U32, verify: U32) ->
  IO(Result<&1, &1, U32 & String, Socket & String>):
  do IO<Result<&1, &1, U32 & String, Socket & String>>:
    r : Result<&1, &1, U32 & String, String> <- DNS.resolve(host)
    tls_dial_any.asked(port, verify, host, r)

def tls_port_any(+host: String, port: U32, verify: U32, ok: Bool) ->
  IO(Result<&1, &1, U32 & String, Socket & String>):
  match ok:
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, Socket & String>,
        Fail{(611, "bad port")})
    case True{}:
      tls_dial_any(host, port, verify)

def tls_connect_any(+host: String, +port: U32) ->
  IO(Result<&1, &1, U32 & String, Socket & String>):
  tls_port_any(host, port, 1, tls_valid_port(port))

def tls_connect_any_insecure(+host: String, +port: U32) ->
  IO(Result<&1, &1, U32 & String, Socket & String>):
  tls_port_any(host, port, 0, tls_valid_port(port))

def tls_alpn_is_h2(protocol: String) -> Bool:
  String.eq(protocol, "h2")

def tls_alpn_is_http1(protocol: String) -> Bool:
  String.eq(protocol, "http/1.1")

# Sends every byte of the list over the TLS socket, handing it back. A
# value past 255 fails with EINVAL before any byte leaves; WANT_READ /
# WANT_WRITE parks on the underlying fd until ready.
def tls_send_bytes(sock: Socket, data: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  import "./effs/tls_send_bytes.c"
  import "./effs/tls_send_bytes.js"

# Receives at most max bytes over the TLS socket as a byte list, handing
# it back; parks on the underlying fd when OpenSSL wants more IO.
def tls_recv_bytes(sock: Socket, max: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  import "./effs/tls_recv_bytes.c"
  import "./effs/tls_recv_bytes.js"

# Shuts the session down, frees it and closes the underlying fd. TLS
# sockets must close here, never via Socket.close.
def tls_close(sock: Socket) -> IO(Unit):
  import "./effs/tls_close.c"
  import "./effs/tls_close.js"

# Resolve-then-handshake. DNS.resolve answers the IPv4 the connect
# rides; the ORIGINAL host rides SNI. A resolve failure fails with the
# DNS code (601-605) before any socket exists. The dial itself is
# Base.TCP.connect's, which owns the fd and its non-blocking mode; alpn
# is the mode above (1 = require h2, 0 = no ALPN).
def tls_dial.dialed(host: String, verify: U32, alpn: U32,
  r: Result<&1, &1, U32 & String, Socket>) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  match r:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, Socket>, Fail{e})
    case Done{sock}:
      do IO<Result<&1, &1, U32 & String, Socket>>:
        conn : Result<&1, &1, U32 & String, Socket & String> <-
          tls_connect_raw(sock, host, verify, alpn)
        tls_connect.without_alpn(conn)

def tls_dial.asked(port: U32, verify: U32, alpn: U32, host: String,
  r: Result<&1, &1, U32 & String, String>) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  match r:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, Socket>, Fail{e})
    case Done{ip}:
      do IO<Result<&1, &1, U32 & String, Socket>>:
        d : Result<&1, &1, U32 & String, Socket> <- TCP.connect(ip, port)
        tls_dial.dialed(host, verify, alpn, d)

def tls_dial(+host: String, port: U32, verify: U32, alpn: U32) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  do IO<Result<&1, &1, U32 & String, Socket>>:
    r : Result<&1, &1, U32 & String, String> <- DNS.resolve(host)
    tls_dial.asked(port, verify, alpn, host, r)

def tls_go(+host: String, port: U32, verify: U32, alpn: U32) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  tls_dial(host, port, verify, alpn)

def tls_port(host: String, port: U32, verify: U32, alpn: U32, ok: Bool) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  match ok:
    case False{}:
      IO.pure(Result<&1, &1, U32 & String, Socket>, Fail{(611, "bad port")})
    case True{}:
      tls_go(host, port, verify, alpn)

# Secure client: verifies the chain, SNIs the original host, ALPN h2.
def tls_connect(+host: String, +port: U32) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  tls_port(host, port, 1, 1, tls_valid_port(port))

# Insecure client: same handshake without chain verification (loopback
# tests with a self-signed cert). Never use it for public hosts.
def tls_connect_insecure(+host: String, +port: U32) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  tls_port(host, port, 0, 1, tls_valid_port(port))

# Secure client with no ALPN offer (WSS / HTTP/1.1 Upgrade over TLS):
# verifies the chain, SNIs the original host, never requires h2.
def tls_connect_noalpn(+host: String, +port: U32) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  tls_port(host, port, 1, 0, tls_valid_port(port))

# Insecure no-ALPN client (WSS loopback with a self-signed cert).
def tls_connect_noalpn_insecure(+host: String, +port: U32) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  tls_port(host, port, 0, 0, tls_valid_port(port))

# Server accept: one TLS handshake over the listener with the cert/key
# at the given paths. The listener is handed back on every path.
def tls_accept.without_alpn(
  m: Listener & Result<&1, &1, U32 & String, Socket & String>) ->
  IO(Listener & Result<&1, &1, U32 & String, Socket>):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener & Result<&1, &1, U32 & String, Socket>,
        (l, Fail{e}))
    case Done{value}:
      (sock, protocol) = value
      IO.pure(Listener & Result<&1, &1, U32 & String, Socket>,
        (l, Done{sock}))

def tls_accept_alpn(listener: Listener, cert: String, key: String) ->
  IO(Listener & Result<&1, &1, U32 & String, Socket & String>):
  tls_accept_raw(listener, cert, key, 2)

def tls_accept_http1(listener: Listener, cert: String, key: String) ->
  IO(Listener & Result<&1, &1, U32 & String, Socket>):
  do IO<Listener & Result<&1, &1, U32 & String, Socket>>:
    m : Listener & Result<&1, &1, U32 & String, Socket & String> <-
      tls_accept_raw(listener, cert, key, 3)
    tls_accept.without_alpn(m)

def tls_accept(listener: Listener, cert: String, key: String) ->
  IO(Listener & Result<&1, &1, U32 & String, Socket>):
  do IO<Listener & Result<&1, &1, U32 & String, Socket>>:
    m : Listener & Result<&1, &1, U32 & String, Socket & String> <-
      tls_accept_raw(listener, cert, key, 1)
    tls_accept.without_alpn(m)
