# lib (tls_alpn_none): the ALPN doorway of the installed pure-JS lane.
#
# Both legs are driven by the five effects in lib/effs/ through the real
# runtime, over one loopback listener: the client dials with
# Base.TCP.connect and the handshake is lib/effs/tls_connect.js's, the
# server accepts with lib/effs/tls_accept.js's. No probe in between, no
# openssl: this rung exists because the 85-rung ladder of
# tests/effs/tls-generic.sh drives the runtime directly and never loaded
# an effect, so nothing measured the files that ship.
#
# The contract in two halves:
#   * a client that offers NO protocol is not a mismatch. RFC 7301 s3.2:
#     the extension is then simply not used. A server with offer=3
#     completes with no protocol selected, and the client asks for none
#     (alpn=0), so both sides answer Done. This is what every WSS client
#     does (TLS.tls_connect_noalpn), and the retired OpenSSL twin
#     answered SSL_TLSEXT_ERR_NOACK here -- the portable lane used to
#     answer 615, which took wsm_loopback_tls from 111 to 11.
#   * a client that DOES offer one we do not serve is 615, on both sides,
#     after the fatal no_application_protocol alert (120) is flushed, so
#     the peer learns why instead of seeing a bare close.
#
# Golden 1111: client refused 615, client accepted, server refused 615,
# server accepted.
import Base
import ../../lib/tls.bend as TLS

def b2u(value: Bool) -> U32:
  match value:
    case True{}:
      1
    case False{}:
      0

# want=615 asserts the refusal and closes the socket if it connected
# anyway; want=0 asserts the connection and closes it. The listener comes
# back on every accept path, like TCP.accept, so one bad peer never costs
# the loop its listener -- each step hands it to the next.
law score_accept:
  for r: Result<&1, &1, (U32 & String), Socket>
  for want: U32
  IO(U32)

def score_accept(r, want):
  match r:
    case Fail{e}:
      (c, t) = e
      IO.pure(U32, b2u(U32.is_eq(c, want)))
    case Done{sock}:
      do IO<U32>:
        closed : Unit <- TLS.tls_close(sock)
        return b2u(U32.is_eq(0, want))

law serve_both:
  for b: Listener & Result<&1, &1, (U32 & String), Socket>
  for refused: U32
  IO(U32)

def serve_both(b, refused):
  (l2, rb) = b
  do IO<U32>:
    accepted : U32 <- score_accept(rb, 0)
    +both : U32 = (refused * 10 + accepted : U32)
    return both

law serve_next:
  for a: Listener & Result<&1, &1, (U32 & String), Socket>
  IO(U32)

def serve_next(a):
  (l1, ra) = a
  do IO<U32>:
    refused : U32 <- score_accept(ra, 615)
    b : Listener & Result<&1, &1, (U32 & String), Socket> <-
      TLS.tls_accept_http1(l1, "tests/io/tls_test_cert.pem",
        "tests/io/tls_test_key.pem")
    serve_both(b, refused)

law serve_two:
  for l: Listener
  IO(U32)

def serve_two(l):
  do IO<U32>:
    a : Listener & Result<&1, &1, (U32 & String), Socket> <-
      TLS.tls_accept_http1(l, "tests/io/tls_test_cert.pem",
        "tests/io/tls_test_key.pem")
    serve_next(a)

# The client half: alpn=1 requires h2 against a server that serves only
# http/1.1, so 615. alpn=0 offers nothing at all, so it completes.
law client_score:
  for r: Result<&1, &1, (U32 & String), Socket>
  for want: U32
  IO(U32)

def client_score(r, want):
  match r:
    case Fail{e}:
      (c, t) = e
      IO.pure(U32, b2u(U32.is_eq(c, want)))
    case Done{sock}:
      do IO<U32>:
        closed : Unit <- TLS.tls_close(sock)
        return b2u(U32.is_eq(0, want))

law listen_retry:
  for port: U32
  for result: Result<&1, &1, (U32 & String), Listener>
  for rest: IO(Listener & U32)
  IO(Listener & U32)

def listen_retry(port, result, rest):
  match result:
    case Done{listener}:
      IO.pure(Listener & U32, (listener, port))
    case Fail{e}:
      rest

law listen_any:
  for tries: Nat
  for +port: U32
  IO(Listener & U32)

def listen_any(tries, port):
  match tries:
    case 0n:
      IO.die(Listener & U32, 1, "no free tcp port")
    case 1n+t:
      rest : IO(Listener & U32) = listen_any(t, (port + 1 : U32))
      do IO<Listener & U32>:
        result : Result<&1, &1, (U32 & String), Listener> <-
          TCP.listen(port)
        listen_retry(port, result, rest)

law main_go:
  for listener: Listener
  for +port: U32
  IO(U32)

def main_go(listener, port):
  do IO<U32>:
    server : Chan(U32) <- IO.fork(U32, serve_two(listener))
    a : Result<&1, &1, (U32 & String), Socket> <-
      TLS.tls_connect_insecure("127.0.0.1", port)
    strict : U32 <- client_score(a, 615)
    c : Result<&1, &1, (U32 & String), Socket> <-
      TLS.tls_connect_noalpn_insecure("127.0.0.1", port)
    loose : U32 <- client_score(c, 0)
    srv : U32 <- IO.join(U32, server)
    +total : U32 = (strict * 1000 + loose * 100 + srv : U32)
    w : Unit <- IO.print(U32.show(total))
    stop : Unit <- IO.die(Unit, 0, "")
    return total

law main_pair:
  for b: Listener & U32
  IO(U32)

def main_pair(b):
  (listener, port) = b
  main_go(listener, port)

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 18777)
    main_pair(b)

#|1111
