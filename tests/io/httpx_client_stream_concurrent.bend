# io (httpx_client_stream_concurrent): the client's concurrent streaming
# lane (task-054 phase 3) against the library's own concurrent server.
#
# The client is HTTPX.client.stream_concurrent_insecure with three
# pipelined requests on one H2 connection: /cancel, /big and /echo. The
# server answers each request at its head: /big answers 70000 bytes,
# which is more than the 65535-byte stream and connection windows, so the
# server slices the body and waits for credit.
#
# Three claims, one point each:
#   * a Cancel at the response head of slot 1 resets only that stream.
#     The DATA frame of that stream is already in flight, is skipped, and
#     only the connection window takes the credit, so the batch ends with
#     the bytes and the finished streams of the two siblings: 70002 and 2.
#   * an empty request list answers Done{(0, 0)} with no dial.
#   * an answer that names another slot fails closed with 502 and never
#     resets a sibling stream.
#
# Without the per-stream credit the big response stalls after 65535 bytes
# and the golden hangs (bounded by the check.sh timeout). Without the
# skip of the in-flight DATA frame the batch fails with 502.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18581

def HOST() -> String:
  "127.0.0.1"

# Above the 65535-byte default window, so the server must wait for credit.
def BIG_LEN() -> U32:
  70000

def TWO() -> List<&2, U32>:
  [99, 99]

# The two bytes of the response that the batch skips.
def BIG_TOTAL() -> U32:
  70002

def FINS() -> U32:
  2

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# Filler bytes, tail-recursive plus one reverse (the mold the task-042
# tests use: a Nat counter builds the list, one x_cat normalizes it).
def fill_go(+n: Nat, +acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      fill_go(p, 46 <> acc)

def big() -> List<&2, U32>:
  HTTP.x_cat(fill_go(U32.to_nat(BIG_LEN()), Nil{}))

# Server: answer at the head, by path. The handler is pure and holds no
# state, so the path is the only key it can use.
def srv_head(path: String) -> HTTP.SrvOut:
  match path:
    case "/big":
      HTTP.RespondEarly{HTTP.Response{200, Nil{}, big()}}
    case _:
      HTTP.RespondEarly{HTTP.Response{200, Nil{}, TWO()}}

def h_srv(ev: HTTP.SrvEv) -> HTTP.SrvOut:
  match ev:
    case HTTP.SrvReqHead{slot, head}:
      match head:
        case HTTP.ReqHead{+method, +path, +headers}:
          srv_head(path)
    case HTTP.SrvReqData{slot, +chunk, fin}:
      HTTP.Continue{}

# Client: cancel the first stream at its response head, continue the
# others. The slot is the only key a pure client handler has.
def h_cli_head(slot: U32) -> HTTP.CStreamOut:
  match slot:
    case 1:
      HTTP.CStreamCancel{1}
    case _:
      HTTP.CStreamContinue{slot}

def h_cli(ev: HTTP.CStreamEv) -> HTTP.CStreamOut:
  match ev:
    case HTTP.CStreamHead{slot, head}:
      h_cli_head(slot)
    case HTTP.CStreamData{slot, +chunk, fin}:
      HTTP.CStreamContinue{slot}

# A handler bug: the answer names a slot that is not the event's slot.
def h_wrong(ev: HTTP.CStreamEv) -> HTTP.CStreamOut:
  match ev:
    case HTTP.CStreamHead{slot, head}:
      HTTP.CStreamContinue{99}
    case HTTP.CStreamData{slot, +chunk, fin}:
      HTTP.CStreamContinue{99}

def reqs() -> List<&2, HTTP.Request>:
  [HTTP.Request{"GET", "/cancel", Nil{}, Nil{}},
    HTTP.Request{"GET", "/big", Nil{}, Nil{}},
    HTTP.Request{"GET", "/echo", Nil{}, Nil{}}]

def reqs_one() -> List<&2, HTTP.Request>:
  [HTTP.Request{"GET", "/echo", Nil{}, Nil{}}]

def counts_ok(counts: U32 & U32) -> U32:
  (total, fins) = counts
  b2u(Bool.and(U32.is_eq(total, BIG_TOTAL()), U32.is_eq(fins, FINS())))

def counts_score(r: Result<&1, &1, U32 & String, U32 & U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{counts}:
      counts_ok(counts)

def empty_ok(counts: U32 & U32) -> U32:
  (total, fins) = counts
  b2u(Bool.and(U32.is_eq(total, 0), U32.is_eq(fins, 0)))

def empty_score(r: Result<&1, &1, U32 & String, U32 & U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{counts}:
      empty_ok(counts)

def mismatch_score(r: Result<&1, &1, U32 & String, U32 & U32>) -> U32:
  match r:
    case Fail{(code, msg)}:
      b2u(Bool.and(U32.is_eq(code, 502), String.eq(msg, "slot mismatch")))
    case Done{counts}:
      0

def batch(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <- HTTPX.client.stream_concurrent_insecure(~h_cli, HOST(), port, reqs())
    IO.pure(U32, counts_score(r))

def empty_batch(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <- HTTPX.client.stream_concurrent_insecure(~h_cli, HOST(), port, Nil{})
    IO.pure(U32, empty_score(r))

def mismatch_batch(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <- HTTPX.client.stream_concurrent_insecure(~h_wrong, HOST(), port, reqs_one())
    IO.pure(U32, mismatch_score(r))

def clients(+port: U32) -> IO(U32):
  do IO<U32>:
    +s1 : U32 <- batch(port)
    +s2 : U32 <- empty_batch(port)
    +s3 : U32 <- mismatch_batch(port)
    IO.pure(U32, (s1 + s2 + s3 : U32))

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTPX.server.stream_concurrent(~h_srv, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    return "up"

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
  (l, port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    +total : U32 <- clients(port)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    main_go(b)

#|3
