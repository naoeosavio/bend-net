# io (httpx_h2_server_seed): the server's response sender must not swallow
# a pipelined request HEADERS it reads while it waits for window credit
# (task-042 phase 2e, the second half of the phase-2b follow-up).
#
# The server is HTTPX.server.concurrent answering 100000 bytes to /big and
# one byte to /small; the client is HTTPX.client.concurrent_insecure
# pipelining both requests on one connection. The big body outruns the
# 65535-byte window, so the server's sender goes back to the socket for
# credit and reads /small's HEADERS — which arrived while the big body was
# going out. Before the fix the flow sender dropped every frame it read
# that was not its own stream's, so the second request was never answered
# and the client hung (bounded by an external timeout); now it stashes the
# frame (re-encoded plus the rest of the recv) and the loop reads those
# bytes first.
#
# Score: one point per response (200 with the expected body), golden 2.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX

def PORT() -> U32:
  18573

def BIG_LEN() -> U32:
  100000

# Filler bytes, tail-recursive plus one reverse (the mold the other task
# 042 tests use).
def fill_go(+n: Nat, +acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      fill_go(p, 46 <> acc)

def big() -> List<&2, U32>:
  HTTPX.x_cat(fill_go(U32.to_nat(BIG_LEN()), Nil{}))

def small() -> List<&2, U32>:
  [46]

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# Server handler: the big body forces the sender to wait for credit.
def h_srv(req: HTTPX.Request) -> IO(HTTPX.Response):
  match req:
    case HTTPX.Request{+method, +path, +headers, +body}:
      match path:
        case "/big":
          IO.pure(HTTPX.Response, HTTPX.Response{200, Nil{}, big()})
        case _:
          IO.pure(HTTPX.Response, HTTPX.Response{200, Nil{}, small()})

# Client scorer: one point per expected body length, nothing else.
def len_score(n: U32, +status: U32) -> U32:
  match n:
    case 100000:
      b2u(U32.is_eq(status, 200))
    case 1:
      b2u(U32.is_eq(status, 200))
    case _:
      0

def h_cli(resp: HTTPX.Response) -> U32:
  match resp:
    case HTTPX.Response{+status, +headers, +body}:
      len_score(HTTPX.x_len32(body), status)

def reqs() -> List<&2, HTTPX.Request>:
  [HTTPX.Request{"GET", "/big", Nil{}, Nil{}}, HTTPX.Request{"GET", "/small", Nil{}, Nil{}}]

def client_score(r: Result<&1, &1, U32 & String, U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+total}:
      total

def client(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32> <- HTTPX.client.concurrent_insecure(~h_cli, "127.0.0.1", port, reqs())
    IO.pure(U32, client_score(r))

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    x : Unit <- HTTPX.server.concurrent(~h_srv, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
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

def run(l: Listener, +port: U32) -> IO(U32):
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    +a : U32 <- client(port)
    +total : U32 = (a : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

def run_bound(b: Listener & U32) -> IO(U32):
  (l, port) = b
  run(l, port)

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    run_bound(b)

#|2
