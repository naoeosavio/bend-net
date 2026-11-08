# io (httpx_h2_client_credit): the client credits the connection window
# of a response body across keep-alive requests (task-063 phase 6b).
#
# The client is HTTP2.client.on: five requests on one connection, in
# order. The server is HTTP2.server.concurrent and answers each request
# with a 20000-byte body. The body is below x_wu_half(), so every frame
# of it stays in the batch until the last one: the END_STREAM frame
# answers the connection remainder alone. Without that remainder the
# client leaks 20000 bytes of the connection window for each request,
# the peer runs out after three, and the fourth body never finishes.
# The second half runs four requests in flight, so their bodies together
# pass the 65535-byte connection window: the concurrent lane needs the
# same credit to finish them.
#
# Checks: one score for each of the five responses with status 200 and a
# 20000-byte body, plus the handler sum of the four concurrent requests
# and the fact that they finish. Golden 7.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18793

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# The body of each answer: below x_wu_half(), so only the last frame of
# it can flush, and above the frame size, so it takes two frames.
def BODY() -> U32:
  20000

# The requests of the run, all on one connection.
def REQUESTS() -> U32:
  5

# The requests in flight, whose bodies together pass the window.
def CONC() -> U32:
  4

def weigh(is_ok: Bool, +weight: U32) -> U32:
  match is_ok:
    case True{}:
      weight
    case False{}:
      0

def fill_go(+n: Nat, +b: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      fill_go(p, b, b <> acc)

def fill(+n: U32, +b: U32) -> List<&2, U32>:
  fill_go(U32.to_nat(n), b, Nil{})

# A good answer: status 200 and the whole body.
def body_ok(resp: HTTP.Response) -> Bool:
  match resp:
    case HTTP.Response{status, headers, body}:
      Bool.and(U32.is_eq(status, 200), U32.is_eq(HTTP.x_len32(body), BODY()))

def oks(+rs: List<&2, HTTP.Response>, acc: U32) -> U32:
  match rs:
    case Nil{}:
      acc
    case +h <> t:
      oks(t, (acc + weigh(body_ok(h), 1) : U32))

def score_of(r: Result<&1, &1, U32 & String, List<&2, HTTP.Response>>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{rs}:
      oks(rs, 0)

# The concurrent lane answers the handler sum: every finished body is
# BODY() bytes, so four of them add up to CONC() * BODY().
def sum_h(resp: HTTP.Response) -> U32:
  match resp:
    case HTTP.Response{status, headers, body}:
      HTTP.x_len32(body)

def conc_score(r: Result<&1, &1, U32 & String, U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+sum}:
      U32.add(1, weigh(U32.is_eq(sum, U32.mul(BODY(), CONC())), 1))

# Builds the request list, one GET for each slot.
def reqs_go(+n: Nat, acc: List<&2, HTTP.Request>) -> List<&2, HTTP.Request>:
  match n:
    case 0n:
      acc
    case 1n+p:
      reqs_go(p, (HTTP.Request{"GET", "/credit", Nil{}, Nil{}} <> acc))

def reqs() -> List<&2, HTTP.Request>:
  reqs_go(U32.to_nat(REQUESTS()), Nil{})

def reqs_n(+n: U32) -> List<&2, HTTP.Request>:
  reqs_go(U32.to_nat(n), Nil{})

def client_side(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, List<&2, HTTP.Response>> <- HTTP2.client.on_insecure(HOST(), port, reqs())
    c : Result<&1, &1, U32 & String, U32> <- HTTP2.client.concurrent_insecure(~sum_h, HOST(), port, reqs_n(CONC()))
    IO.pure(U32, U32.add(score_of(r), conc_score(c)))

# --- the server side ------------------------------------------------

def big_h(req: HTTP.Request) -> IO(HTTP.Response):
  IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, fill(BODY(), 120)})

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    x : Unit <- HTTP2.server.concurrent(~big_h, l, CERT(), KEY())
    return "up"

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
    chan : Chan(String) <- IO.fork(String, server_side(l))
    +score : U32 <- client_side(port)
    w : Unit <- IO.print(U32.show(score))
    z : Unit <- IO.die(Unit, 0, "")
    return score

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    run(b)

#|7
