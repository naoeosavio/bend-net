# io (h2_duplex_credit): two library endpoints on one connection send large
# bodies at the same time (task-068). The client puts two 200000-byte POSTs
# in flight and the server echoes each body. The response of request 1 is on
# the wire while the client writes the body of request 2, so each send pump
# parks and waits for the credit of its own receive side.
#
# A send pump that stashes a DATA frame must credit that frame at once
# (RFC 9113 section 6.9.1). Before the fix the pump stashed the frame and the
# loop credited the bytes only after the send ended: both endpoints waited
# for each other and the cell stopped at the gate ceiling.
#
# Checks: status 200 and the echoed 200000-byte body for each response, so
# the handler sum is 400000. Golden 400000.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18840

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# One body per request, above the 65535-byte stream and connection window.
def BODY() -> U32:
  200000

def BODY_B() -> U32:
  120

# The requests in flight: response 1 leaves the server while the client
# writes the body of request 2.
def REQUESTS() -> U32:
  2

def fill_go(+n: Nat, +b: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      fill_go(p, b, b <> acc)

def fill(n: U32) -> List<&2, U32>:
  fill_go(U32.to_nat(n), BODY_B(), Nil{})

def reqs_go(+n: Nat, acc: List<&2, HTTP.Request>) -> List<&2, HTTP.Request>:
  match n:
    case 0n:
      acc
    case 1n+p:
      reqs_go(p, (HTTP.Request{"POST", "/echo", Nil{}, fill(BODY())} <> acc))

def reqs() -> List<&2, HTTP.Request>:
  reqs_go(U32.to_nat(REQUESTS()), Nil{})

def weigh(is_ok: Bool, +weight: U32) -> U32:
  match is_ok:
    case True{}:
      weight
    case False{}:
      0

# The handler sum: the body length of a 200 answer, and zero otherwise.
def sum_h(resp: HTTP.Response) -> U32:
  match resp:
    case HTTP.Response{+status, +headers, +body}:
      +ok : Bool = Bool.and(U32.is_eq(status, 200), U32.is_eq(HTTP.x_len32(body), BODY()))
      weigh(ok, BODY())

def score(r: Result<&1, &1, U32 & String, U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+sum}:
      sum

def client_side(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32> <-
      HTTP2.client.concurrent_insecure(~sum_h, HOST(), port, reqs())
    IO.pure(U32, score(r))

def big_h(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{method, path, headers, body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, body})

def server_side(l: Listener) -> IO(Unit):
  do IO<Unit>:
    x : Unit <- HTTP2.server.concurrent(~big_h, l, CERT(), KEY())
    IO.pure(Unit, Unit{})

def listen_retry(port: U32, r: Result<&1, &1, (U32 & String), Listener>, rest: IO(Listener & U32)) -> IO(Listener & U32):
  match r:
    case Done{l}:
      IO.pure(Listener & U32, (l, port))
    case Fail{e}:
      rest

def listen_any(tries: Nat, +port: U32) -> IO(Listener & U32):
  match tries:
    case 0n:
      IO.die(Listener & U32, 1, "no free tcp port")
    case 1n+t:
      rest = listen_any(t, (port + 1 : U32))
      do IO<Listener & U32>:
        r : Result<&1, &1, (U32 & String), Listener> <- TCP.listen(port)
        listen_retry(port, r, rest)

def run(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l))
    +score : U32 <- client_side(port)
    w : Unit <- IO.print(U32.show(score))
    z : Unit <- IO.die(Unit, 0, "")
    return score

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    run(b)

#|400000
