# TLS over TCP: package-local byte effects with OpenSSL below (no Base
# patch). The public lane is tls_connect / tls_connect_insecure plus the
# server accept and the byte send/recv/close twins of lib/tcp.bend.
#
# The TLS socket handle is an SSL* pointer packed as a Socket (never a
# raw fd): it must ONLY ride TLS.send/recv/close, never Base TCP or
# Socket.close (which would leak the SSL session). Every effect hands
# the socket back beside its Result, like TCP.send_bytes does.
#
# Fail codes are stable numbers, never OpenSSL text: 611 bad input
# (port/host), 612 dial failed (TCP connect), 613 handshake failed,
# 614 verify failed, 615 ALPN mismatch (expected h2), 616 IO error
# (send/recv/accept). DNS failures keep their 601-605 codes and surface
# before any socket exists, so no handle can leak.
#
# Transport invariant (same as HTTP fetch.dial): DNS.resolve answers the
# IPv4 the connect rides; the ORIGINAL host rides SNI and (later) the
# :authority/Host header, so virtual hosting never changes.
#
# Import as: import ./tls.bend as TLS (from lib) or
# import ../../lib/tls.bend as TLS (from tests/io).
# Then TLS.tls_connect, TLS.tls_connect_insecure, TLS.tls_connect_noalpn,
# TLS.tls_connect_noalpn_insecure, TLS.tls_accept, TLS.tls_send_bytes,
# TLS.tls_recv_bytes, TLS.tls_close.
import Base
import ./dns.bend as DNS

# The raw client handshake: connects to the IPv4 ip, SNIs sni, verifies
# the chain iff verify is 1. ALPN mode: alpn=1 offers and requires h2
# (HTTPS); alpn=0 offers nothing and accepts no protocol negotiation
# (WSS/HTTP/1.1 Upgrade). Answers the TLS socket (SSL*) on Done. Host
# validation lives above (DNS.resolve); port validation lives above
# (tls_port).
def tls_connect_raw(ip: String, sni: String, port: U32, verify: U32, alpn: U32) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  import "./effs/tls_connect.c"
  import "./effs/tls_connect.js"

# The raw server handshake: accepts one TCP connection on listener,
# handshakes it with cert/key at the given file paths, negotiates ALPN
# h2. Hands the listener back beside the TLS socket, like TCP.accept.
def tls_accept_raw(listener: Listener, cert: String, key: String) ->
  IO(Listener & Result<&1, &1, U32 & String, Socket>):
  import "./effs/tls_accept.c"
  import "./effs/tls_accept.js"

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

# Ports must be 1..65535, like HTTP valid_port.
def tls_valid_port(+p: U32) -> Bool:
  Bool.and(U32.is_ge(p, 1), U32.is_le(p, 65535))

# Resolve-then-handshake. DNS.resolve answers the IPv4 the connect
# rides; the ORIGINAL host rides SNI. A resolve failure fails with the
# DNS code (601-605) before any socket exists. alpn is the mode above
# (1 = require h2, 0 = no ALPN).
def tls_dial.asked(port: U32, verify: U32, alpn: U32, host: String, r: Result<&1, &1, U32 & String, String>) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  match r:
    case Fail{e}:
      IO.pure(Result<&1, &1, U32 & String, Socket>, Fail{e})
    case Done{ip}:
      tls_connect_raw(ip, host, port, verify, alpn)

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
def tls_accept(listener: Listener, cert: String, key: String) ->
  IO(Listener & Result<&1, &1, U32 & String, Socket>):
  tls_accept_raw(listener, cert, key)
