# io (httpx_h2_loop_on): the sequential lane over the byte loop (task-058
# phase 1, the E1 winner). One connection answers three requests in order
# through client.loop.on, then one 8 KB answer through client.loop.exch on
# the same state. The counts of every exchange and the sid of the CliSt are
# the score, so the table and the sid must travel from request to request.
#
# Score: 3 empty answers +1, 8 KB counts +2, sid 9 after four +1, golden 4.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18620

def TRIES() -> Nat:
  32n

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

def HOST() -> String:
  "127.0.0.1"

# This def answers the weight when the check passed, and zero otherwise.
def weigh(is_ok: Bool, +weight: U32) -> U32:
  match is_ok:
    case True{}:
      weight
    case False{}:
      0

def bytes.go(n: Nat, +b: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      bytes.go(p, b, b <> acc)

def bytes(n: Nat, +b: U32) -> List<&2, U32>:
  bytes.go(n, b, Nil{})

def echo.go(is_8k: Bool) -> IO(HTTP.Response):
  match is_8k:
    case True{}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, bytes(8192n, 120)})
    case False{}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, Nil{}})

def echo(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      echo.go(String.eq(path, "/8k"))

# The streaming handler: continue every event, so the loop counts the
# answer instead of accumulating it.
def h_cont(ev: HTTP.StreamEv) -> HTTP.StreamOut:
  HTTP.StreamContinue{}

def one(+path: String) -> HTTP.Request:
  HTTP.Request{"GET", path, Nil{}, Nil{}}

def three() -> List<&2, HTTP.Request>:
  one("/empty") <> (one("/empty") <> (one("/empty") <> Nil{}))

def score_counts(r: Result<&1, &1, U32 & String, U32 & U32>, +want_tot: U32, +want_fin: U32, +weight: U32) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{counts}:
      match counts:
        case (tot, fin):
          weigh(Bool.and(U32.is_eq(tot, want_tot), U32.is_eq(fin, want_fin)),
            weight)

# This def scores the sid the loop carried to the next request.
def score_sid(st: HTTP.CliSt, +want: U32, +weight: U32) -> U32:
  weigh(U32.is_eq(HTTP2.client.loop.st_sid(st), want), weight)

law run.last:
  for out: Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt
  IO(U32)

def run.last(out):
  (s, r, st) = out
  do IO<U32>:
    +a : U32 = score_counts(r, 8192, 1, 2)
    +b : U32 = score_sid(st, 9, 1)
    x : Unit <- TLS.tls_close(s)
    IO.pure(U32, (a + b : U32))

law run.exch:
  for s: Socket
  for st: HTTP.CliSt
  IO(U32)

def run.exch(s, st):
  do IO<U32>:
    out : Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt <-
      HTTP2.client.loop.exch(~h_cont, s, st, HOST(), PORT(), one("/8k"))
    run.last(out)

law run.eight:
  for out: Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt
  for +a: U32
  for +b: U32
  IO(U32)

def run.eight(out, a, b):
  (s, r, st) = out
  do IO<U32>:
    +c : U32 = score_counts(r, 0, 3, 1)
    +e : U32 <- run.exch(s, st)
    IO.pure(U32, (a + (b + (c + e)) : U32))

law run_conn:
  for conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>
  IO(U32)

def run_conn(conn):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, st) = value
      do IO<U32>:
        out : Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt <-
          HTTP2.client.loop.on(~h_cont, sock, st, HOST(), PORT(), three())
        run.eight(out, 0, 0)

law client:
  IO(U32)

def client():
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <-
      HTTP2.client.connect_insecure(HOST(), PORT())
    run_conn(conn)

law server_side:
  for l: Listener
  IO(Unit)

def server_side(l):
  do IO<Unit>:
    x : Unit <- HTTP2.server.concurrent(~echo, l, CERT(), KEY())
    IO.pure(Unit, Unit{})

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
  for b: Listener & U32
  IO(U32)

def main_go(b):
  (l, +port) = b
  do IO<U32>:
    c : Chan(Unit) <- IO.fork(Unit, server_side(l))
    +total : U32 <- client()
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(TRIES(), PORT())
    main_go(b)

#|4
