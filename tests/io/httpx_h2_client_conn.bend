# io (httpx_h2_client_conn): the H2 module dials itself (task-058 phase 0).
#
# The module is H2 only, so the dial must refuse any peer that does not
# answer h2 in the ALPN handshake. Two peers prove it:
#   - an h2 peer: HTTP2.request_insecure POST "hello" must echo it, which
#     only passes after the preface and the SETTINGS frame went out.
#   - a peer that does not answer h2: the same one-shot lane must fail
#     615 before it sends a byte. No HTTP/1.1 arm exists here.
#
# Score: h2 echo +1, 615 +2, golden 3.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

# Port of the h2 peer and of the refusing peer.
def H2_PORT() -> U32:
  18600

def OTHER_PORT() -> U32:
  18610

# Ports to try before the test gives up.
def TRIES() -> Nat:
  32n

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

def LOCAL() -> String:
  "127.0.0.1"

# This def answers the weight when the check passed, and zero otherwise.
def weigh(is_ok: Bool, +weight: U32) -> U32:
  match is_ok:
    case True{}:
      weight
    case False{}:
      0

def echo(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, body})

# h2 peer: the lane must answer.
# ---------------------------------------------------------------------

# This def scores the text answer of the H2 one-shot lane.
def text_score(r: Result<&1, &1, U32 & String, String>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+body}:
      weigh(String.eq(body, "hello"), 1)

def h2_text(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, String> <-
      HTTP2.request_insecure(LOCAL(), port, "/echo", "POST", Nil{}, "hello")
    IO.pure(U32, text_score(r))

# Non-h2 peer: the lane must refuse it with 615.
# ---------------------------------------------------------------------

# This def scores the failure code of a peer that does not answer h2.
def code_score(e: U32 & String) -> U32:
  (code, msg) = e
  weigh(U32.is_eq(code, 615), 2)

def code_615(r: Result<&1, &1, U32 & String, String>) -> U32:
  match r:
    case Fail{e}:
      code_score(e)
    case Done{+body}:
      0

def other_615(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, String> <-
      HTTP2.request_insecure(LOCAL(), port, "/echo", "POST", Nil{}, "hello")
    IO.pure(U32, code_615(r))

# Peers and driver
# ---------------------------------------------------------------------

law h2_side:
  for l: Listener
  IO(Unit)

def h2_side(l):
  do IO<Unit>:
    x : Unit <- HTTPX.server.concurrent(~echo, l, CERT(), KEY())
    IO.pure(Unit, Unit{})

# The refusing peer answers one handshake and stops. The ALPN lists do not
# overlap, so both sides fail 615 and no request byte is ever sent.
def other_end(m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(Unit):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Unit, Unit{})
    case Done{sock}:
      TLS.tls_close(sock)

law other_side:
  for l: Listener
  IO(Unit)

def other_side(l):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <-
      TLS.tls_accept_http1(l, CERT(), KEY())
    other_end(m)

law drive:
  for h2p: U32
  for otherp: U32
  IO(U32)

def drive(h2p, otherp):
  do IO<U32>:
    +a : U32 <- h2_text(h2p)
    +b : U32 <- other_615(otherp)
    IO.pure(U32, (a + b : U32))

law listen_retry:
  for port: U32
  for r: Result<&1, &1, (U32 & String), Listener>
  for rest: IO(Listener & U32)
  IO(Listener & U32)

def listen_retry(port, r, rest):
  match r:
    case Done{l}:
      IO.pure(Listener & U32, (l, port))
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
      rest = listen_any(t, (port + 1 : U32))
      do IO<Listener & U32>:
        r : Result<&1, &1, (U32 & String), Listener> <- TCP.listen(port)
        listen_retry(port, r, rest)

law main_go:
  for b2: Listener & U32
  for b1: Listener & U32
  IO(U32)

def main_go(b2, b1):
  (l2, +h2p) = b2
  (l1, otherp) = b1
  do IO<U32>:
    c2 : Chan(Unit) <- IO.fork(Unit, h2_side(l2))
    c1 : Chan(Unit) <- IO.fork(Unit, other_side(l1))
    +total : U32 <- drive(h2p, otherp)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b2 : Listener & U32 <- listen_any(TRIES(), H2_PORT())
    b1 : Listener & U32 <- listen_any(TRIES(), OTHER_PORT())
    main_go(b2, b1)

#|3
