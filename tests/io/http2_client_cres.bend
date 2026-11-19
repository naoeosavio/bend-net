# io (http2_client_cres): the one answer of the client loop and the one
# batch path (task-081). A single CRes serves every mode, and the two
# concurrent lanes share the batch send.
#
# One connection runs four projections in a row:
#   - client.request twice (buffered, collect on): the sink of CRes holds
#     the answer, and the table and the sid travel in the CliSt;
#   - client.loop.exch once (stream): the counts of CRes hold the answer;
#   - client.loop.on twice (stream, in order): the counts of each exchange
#     add up, and the next sid advances by two on every exchange.
# A lost table, window or sid fails the exchange that follows.
#
# A second listener answers the two concurrent lanes over the same shared
# batch path: client.concurrent (buffered, handler sum) and
# client.stream.concurrent (stream, counts).
#
# Score: two buffered answers +2, one streamed exchange +2, two streamed
# answers +2, the final sid +1, buffered batch +2, streamed batch +2,
# golden 11.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def HOST() -> String:
  "127.0.0.1"

def PORT() -> U32:
  18810

def PORT_BATCH() -> U32:
  18820

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

def BODY() -> String:
  "hi"

def body_bytes() -> List<&2, U32>:
  HTTP.x_str_bytes(BODY())

def echo_req() -> HTTP.Request:
  HTTP.Request{"GET", "/echo", Nil{}, Nil{}}

# The buffered handler: a 200 answer with the two-byte body.
def echo(req: HTTP.Request) -> IO(HTTP.Response):
  IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, body_bytes()})

# This def answers the weight when the check passed, and zero otherwise.
def weigh(is_ok: Bool, +weight: U32) -> U32:
  match is_ok:
    case True{}:
      weight
    case False{}:
      0

# The stream handler: continue every event, so the loop counts the answer.
def hc(ev: HTTP.StreamEv) -> HTTP.StreamOut:
  HTTP.StreamContinue{}

# The concurrent handler: continue every event of its stream.
def hcs(ev: HTTP.CStreamEv) -> HTTP.CStreamOut:
  match ev:
    case HTTP.CStreamHead{+slot, +head}:
      HTTP.CStreamContinue{slot}
    case HTTP.CStreamData{+slot, +chunk, +fin}:
      HTTP.CStreamContinue{slot}

# One response scores one point when its status is 200.
def score_resp(r: Result<&1, &1, U32 & String, HTTP.Response>, +weight: U32) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      match resp:
        case HTTP.Response{+status, +headers, +body}:
          weigh(U32.is_eq(status, 200), weight)

# One count pair scores its weight when both numbers match.
def score_counts(r: Result<&1, &1, U32 & String, U32 & U32>, +wt: U32, +wf: U32, +weight: U32) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{counts}:
      match counts:
        case (t, f):
          weigh(Bool.and(U32.is_eq(t, wt), U32.is_eq(f, wf)), weight)

# The next sid of the carried state scores its weight when it matches.
def score_sid(st: HTTP.CliSt, +want: U32, +weight: U32) -> U32:
  weigh(U32.is_eq(HTTP2.client.loop.st_sid(st), want), weight)

# Closes the socket and answers the score.
def mix_close(out: Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt, +acc: U32) -> IO(U32):
  (sock, r, st) = out
  do IO<U32>:
    +a : U32 = (acc + score_counts(r, 4, 2, 2) : U32)
    +b : U32 = (a + score_sid(st, 11, 1) : U32)
    x : Unit <- TLS.tls_close(sock)
    IO.pure(U32, b)

# Runs the two ordered streamed exchanges over loop.on.
def mix_on(out: Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt, +acc: U32) -> IO(U32):
  (sock, r, st) = out
  do IO<U32>:
    +a : U32 = (acc + score_counts(r, 2, 1, 2) : U32)
    out2 : Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt <-
      HTTP2.client.loop.on(~hc, sock, st, HOST(), PORT(),
        [echo_req(), echo_req()])
    mix_close(out2, a)

# Runs one streamed exchange over loop.exch.
def mix_exch(out: Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt, +acc: U32) -> IO(U32):
  (sock, r, st) = out
  do IO<U32>:
    +a : U32 = (acc + score_resp(r, 1) : U32)
    out2 : Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt <-
      HTTP2.client.loop.exch(~hc, sock, st, HOST(), PORT(), echo_req())
    mix_on(out2, a)

# Runs the second buffered exchange over client.request.
def mix_req2(out: Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt, +acc: U32) -> IO(U32):
  (sock, r, st) = out
  do IO<U32>:
    +a : U32 = (acc + score_resp(r, 1) : U32)
    out2 : Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt <-
      HTTP2.client.request(sock, st, HOST(), PORT(), echo_req())
    mix_exch(out2, a)

# Runs the first buffered exchange over client.request.
def mix_req1(conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>, +acc: U32) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, acc)
    case Done{value}:
      (sock, st) = value
      do IO<U32>:
        out : Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt <-
          HTTP2.client.request(sock, st, HOST(), PORT(), echo_req())
        mix_req2(out, acc)

# One point for a 200 answer of the buffered batch handler.
def plain(resp: HTTP.Response) -> U32:
  match resp:
    case HTTP.Response{+status, +headers, +body}:
      weigh(U32.is_eq(status, 200), 1)

# The handler sum of a buffered batch, scored against the wanted sum.
def batch_sum(r: Result<&1, &1, U32 & String, U32>, +want: U32) -> IO(U32):
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{+n}:
      IO.pure(U32, weigh(U32.is_eq(n, want), 2))

# The buffered batch: the handler sum over the ledger scores two points.
def batch_buf(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32> <-
      HTTP2.client.concurrent_insecure(~plain, HOST(), port,
        [echo_req(), echo_req()])
    batch_sum(r, 2)

# The stream batch: the counts of the shared batch path score two points.
def batch_str(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <-
      HTTP2.client.stream.concurrent_insecure(~hcs, HOST(), port,
        [echo_req(), echo_req()])
    IO.pure(U32, score_counts(r, 4, 2, 2))

law server_mix:
  for l: Listener
  IO(String)

def server_mix(l):
  do IO<String>:
    x : Unit <- HTTP2.server.on(~echo, l, CERT(), KEY())
    return "up"

law server_batch:
  for l: Listener
  IO(String)

def server_batch(l):
  do IO<String>:
    x : Unit <- HTTP2.server.concurrent(~echo, l, CERT(), KEY())
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

law mix_all:
  for b: Listener & U32
  for b2: Listener & U32
  IO(U32)

def mix_all(b, b2):
  (l1, port1) = b
  (l2, port2) = b2
  do IO<U32>:
    +p2 : U32 = port2
    c1 : Chan(String) <- IO.fork(String, server_mix(l1))
    c2 : Chan(String) <- IO.fork(String, server_batch(l2))
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <-
      HTTP2.client.connect_insecure(HOST(), port1)
    +s1 : U32 <- mix_req1(conn, 0)
    +s2 : U32 <- batch_buf(p2)
    +s3 : U32 <- batch_str(p2)
    +total : U32 = (s1 + (s2 + s3) : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    b2 : Listener & U32 <- listen_any(32n, PORT_BATCH())
    x : U32 <- mix_all(b, b2)
    return x

#|11
