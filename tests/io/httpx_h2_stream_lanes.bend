# io (httpx_h2_stream_lanes): the three event lanes of the H2 module
# (task-058 phase 2). One h2 peer answers all of them, and each lane
# dials, runs its loop and closes:
#   - client.stream.once: one POST with a two-byte body, so the answer is
#     a head plus one DATA frame. Counts must be (2, 1).
#   - client.stream.on: two GET in order on one connection. Counts must be
#     (0, 2), one end for each answer.
#   - client.stream.concurrent: the same two GET in flight. Counts must be
#     (0, 2).
#
# Score: once +1, on +2, concurrent +4, golden 7.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18630

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

def echo(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, body})

# The event handlers: continue every event, so the lanes only count.
def h_cont(ev: HTTP.StreamEv) -> HTTP.StreamOut:
  HTTP.StreamContinue{}

def h_ccont(ev: HTTP.CStreamEv) -> HTTP.CStreamOut:
  match ev:
    case HTTP.CStreamHead{+slot, +head}:
      HTTP.CStreamContinue{slot}
    case HTTP.CStreamData{+slot, +chunk, +fin}:
      HTTP.CStreamContinue{slot}

def one() -> HTTP.Request:
  HTTP.Request{"GET", "/echo", Nil{}, Nil{}}

def two() -> List<&2, HTTP.Request>:
  one() <> (one() <> Nil{})

def score_counts(r: Result<&1, &1, U32 & String, U32 & U32>, +want_tot: U32, +want_fin: U32, +weight: U32) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{counts}:
      match counts:
        case (tot, fin):
          weigh(Bool.and(U32.is_eq(tot, want_tot), U32.is_eq(fin, want_fin)),
            weight)

law lane_once:
  IO(U32)

def lane_once():
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <-
      HTTP2.client.stream.once_insecure(~h_cont, HOST(), PORT(), "POST",
        "/echo", Nil{}, HTTP.x_str_bytes("ab"))
    IO.pure(U32, score_counts(r, 2, 1, 1))

law lane_on:
  IO(U32)

def lane_on():
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <-
      HTTP2.client.stream.on_insecure(~h_cont, HOST(), PORT(), two())
    IO.pure(U32, score_counts(r, 0, 2, 2))

law lane_conc:
  IO(U32)

def lane_conc():
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <-
      HTTP2.client.stream.concurrent_insecure(~h_ccont, HOST(), PORT(), two())
    IO.pure(U32, score_counts(r, 0, 2, 4))

law drive:
  IO(U32)

def drive():
  do IO<U32>:
    +a : U32 <- lane_once()
    +b : U32 <- lane_on()
    +c : U32 <- lane_conc()
    IO.pure(U32, (a + (b + c) : U32))

law server_side:
  for l: Listener
  IO(Unit)

def server_side(l):
  do IO<Unit>:
    x : Unit <- HTTPX.server.concurrent(~echo, l, CERT(), KEY())
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
    +total : U32 <- drive()
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(TRIES(), PORT())
    main_go(b)

#|7
