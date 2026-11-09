# io (http2_pq_batch): the buffered server answers after the read batch
# (task-072 phase 2).
#
# The buffered lane keeps a stream open while its answer waits in the
# queue. It reads one chunk and admits every frame of the chunk before it
# answers one, so the stream cap sees the batch the way node does. Four
# connections, one claim each, score 4:
#   * a peer that sends 129 complete HEADERS in one write gets RST_STREAM
#     7 on stream 257 before any 200;
#   * a peer that first announces INITIAL_WINDOW_SIZE 0 and then sends the
#     same batch gets RST_STREAM 7 on stream 257, because no answer can
#     start and every stream stays open;
#   * a peer that opens a stream, cancels it with RST_STREAM, then opens
#     the window and opens another stream gets the answer of the second
#     stream only;
#   * a peer that opens a stream at a zero window and then grants one
#     octet on the stream gets the first DATA frame of the answer.
# Before the fix the lane answered each HEADERS before it read the next,
# so the ledger never reached the cap (h2spec 5.1.2.1, task-072).
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18974

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# The cap of x_max_streams, and the sid of the stream it refuses.
def CAP() -> Nat:
  128n

def REFUSED_SID() -> U32:
  257

# The sid the third connection cancels, and the sid it answers.
def CANCEL_SID() -> U32:
  1

def LIVE_SID() -> U32:
  3

# REFUSED_STREAM, the code of the refusal.
def REFUSED() -> U32:
  7

# CANCEL, the code of the peer reset.
def CANCEL() -> U32:
  8

# The initial window the third connection opens at the end.
def WIN_OPEN() -> U32:
  65535

# Frames the peer reads before it gives up.
def FUEL() -> Nat:
  256n

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# One complete request: HEADERS with END_HEADERS and END_STREAM.
def head_frame(+sid: U32) -> List<&2, U32>:
  HTTP2.x_frame_write(HTTP2.x_t_headers(), (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32), sid,
    HTTP2.client.on.req_block(HOST(), PORT(), "GET", "/pq", Nil{}))

def settings_frame(+v: U32) -> List<&2, U32>:
  HTTP2.x_frame_write(HTTP2.x_t_settings(), 0, 0, List.append(&2, U32, HTTP2.x_be16(4), HTTP.x_be32(v)))

def rst_frame(+sid: U32) -> List<&2, U32>:
  HTTP2.x_frame_write(HTTP2.x_t_rst(), 0, sid, HTTP.x_be32(CANCEL()))

def wu_frame(+sid: U32, +inc: U32) -> List<&2, U32>:
  HTTP2.x_frame_write(HTTP2.x_t_wu(), 0, sid, HTTP.x_be32(inc))

# The batch bytes: one HEADERS per stream, sids 1, 3, ... REFUSED_SID. The
# walk starts at the last sid and prepends, so the batch reads ascending.
def batch_go(n: Nat, +sid: U32, +acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      batch_go(p, (sid - 2 : U32), List.append(&2, U32, head_frame(sid), acc))

def batch() -> List<&2, U32>:
  batch_go(Nat.add(CAP(), 1n), REFUSED_SID(), Nil{})

def sock_of(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

def send_bytes(s: Socket, +bs: List<&2, U32>) -> IO(Socket):
  do IO<Socket>:
    w : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(s, bs)
    IO.pure(Socket, sock_of(w))

def close_score(s: Socket, +n: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    IO.pure(U32, n)

def close_got(got: Socket & HTTP.Got, +n: U32) -> IO(U32):
  (s, g) = got
  close_score(s, n)

# The verdict of one frame on a batch: 1 the refusal of REFUSED_SID, 2 an
# answer of any stream, 0 any other frame.
def batch_verdict(+typ: U32, +sid: U32, +payload: List<&2, U32>) -> U32:
  +rst : U32 = HTTP2.x_pick(Bool.and(U32.is_eq(typ, HTTP2.x_t_rst()), U32.is_eq(sid, REFUSED_SID())), HTTP2.x_pick(U32.is_eq(HTTP2.x_rst.code(payload), REFUSED()), 1, 0), 0)
  +heads : U32 = HTTP2.x_pick(U32.is_eq(typ, HTTP2.x_t_headers()), 2, 0)
  U32.max(rst, heads)

# One frame walk: phase 0 reads a frame, phase 1 dispatches it, phase 2
# acts on the verdict. @unsafe: the phase ping-pong does not shrink a
# structural argument, and FUEL bounds it.
@unsafe
def batch_walk(ph: U32, fuel: Nat, got: Socket & HTTP.Got, +verdict: U32, +buf: List<&2, U32>) -> IO(U32):
  match ph fuel:
    case 0 0n:
      close_got(got, 0)
    case 0 _:
      do IO<U32>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(HTTP2.httpx.got_sock(got), buf)
        batch_walk(1, Nat.sub(fuel, 1n), got2, 0, buf)
    case 1 _:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          close_score(s1, 0)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
              batch_walk(2, fuel, (s1, HTTP.GotOk{frame, buf2}), batch_verdict(typ, sid, payload), buf2)
    case _ _:
      match verdict:
        case 1:
          close_got(got, 1)
        case 2:
          close_got(got, 0)
        case _:
          batch_walk(0, fuel, got, 0, buf)

# The verdict of one frame on a later connection: 1 the frame the test
# waits, 2 the frame that fails it, 0 any other frame. Stage 2 is the
# canceled stream: a HEADERS on LIVE_SID answers, a HEADERS on CANCEL_SID
# fails. Stage 3 is the opened window: a DATA frame on CANCEL_SID answers.
def pq_verdict(stage: U32, +typ: U32, +sid: U32) -> U32:
  match stage:
    case 2:
      +heads : U32 = HTTP2.x_pick(U32.is_eq(typ, HTTP2.x_t_headers()), 1, 0)
      HTTP2.x_pick(U32.is_eq(sid, LIVE_SID()), heads, HTTP2.x_pick(U32.is_eq(sid, CANCEL_SID()), U32.mul(heads, 2), 0))
    case _:
      HTTP2.x_pick(Bool.and(U32.is_eq(typ, HTTP2.x_t_data()), U32.is_eq(sid, CANCEL_SID())), 1, 0)

# The same walk on a later connection. 1 for the frame the stage waits, 2
# for the frame that fails it, 0 for any other frame.
@unsafe
def frame_walk(ph: U32, fuel: Nat, got: Socket & HTTP.Got, +stage: U32, +verdict: U32, +buf: List<&2, U32>) -> IO(U32):
  match ph fuel:
    case 0 0n:
      close_got(got, 0)
    case 0 _:
      do IO<U32>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(HTTP2.httpx.got_sock(got), buf)
        frame_walk(1, Nat.sub(fuel, 1n), got2, stage, 0, buf)
    case 1 _:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          close_score(s1, 0)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
              frame_walk(2, fuel, (s1, HTTP.GotOk{frame, buf2}), stage, pq_verdict(stage, typ, sid), buf2)
    case _ _:
      match verdict:
        case 1:
          close_got(got, 1)
        case 2:
          close_got(got, 0)
        case _:
          frame_walk(0, fuel, got, stage, 0, buf)

# Connection 1: the whole batch in one write, at the default window.
def conn_batch(s: Socket) -> IO(U32):
  do IO<U32>:
    s1 : Socket <- send_bytes(s, batch())
    batch_walk(0, FUEL(), (s1, HTTP.GotErr{0, "next"}), 0, Nil{})

# Connection 2: the same batch after a zero initial window, so no answer
# can start on the wire.
def conn_zero(s: Socket) -> IO(U32):
  do IO<U32>:
    s1 : Socket <- send_bytes(s, List.append(&2, U32, settings_frame(0), batch()))
    batch_walk(0, FUEL(), (s1, HTTP.GotErr{0, "next"}), 0, Nil{})

# Connection 3: a zero window, one canceled stream, the window open again
# and one live stream, all in one write.
def conn_cancel(s: Socket) -> IO(U32):
  do IO<U32>:
    s1 : Socket <- send_bytes(s, List.append(&2, U32, settings_frame(0), List.append(&2, U32, head_frame(CANCEL_SID()), List.append(&2, U32, rst_frame(CANCEL_SID()), List.append(&2, U32, settings_frame(WIN_OPEN()), head_frame(LIVE_SID()))))))
    frame_walk(0, FUEL(), (s1, HTTP.GotErr{0, "next"}), 2, 0, Nil{})

# Connection 4: a zero window, one request, and then one octet of stream
# credit. The answer waits in the queue and the grant wakes it.
def conn_wu(s: Socket) -> IO(U32):
  do IO<U32>:
    s1 : Socket <- send_bytes(s, List.append(&2, U32, settings_frame(0), List.append(&2, U32, head_frame(CANCEL_SID()), wu_frame(CANCEL_SID(), 1))))
    frame_walk(0, FUEL(), (s1, HTTP.GotErr{0, "next"}), 3, 0, Nil{})

# The stage of one peer connection: 0 the batch, 1 the zero window, 2 the
# canceled stream.
def peer_conn(conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>, +stage: U32) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, st) = value
      match stage:
        case 0:
          conn_batch(sock)
        case 1:
          conn_zero(sock)
        case 2:
          conn_cancel(sock)
        case _:
          conn_wu(sock)

def peer_go(+port: U32) -> IO(U32):
  do IO<U32>:
    c1 : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTP2.client.connect_insecure(HOST(), port)
    +a : U32 <- peer_conn(c1, 0)
    c2 : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTP2.client.connect_insecure(HOST(), port)
    +b2 : U32 <- peer_conn(c2, 1)
    c3 : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTP2.client.connect_insecure(HOST(), port)
    +c3s : U32 <- peer_conn(c3, 2)
    c4 : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTP2.client.connect_insecure(HOST(), port)
    +c4s : U32 <- peer_conn(c4, 3)
    +score : U32 = U32.add(a, U32.add(b2, U32.add(c3s, c4s)))
    w : Unit <- IO.print(U32.show(score))
    z : Unit <- IO.die(Unit, 0, "")
    return score

# The real buffered concurrent lane.
# The answer carries a two-octet body. The fourth connection needs a body:
# the one octet of stream credit wakes a DATA frame, and the walk waits
# for it.
def echo(req: HTTP.Request) -> IO(HTTP.Response):
  IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, [104, 105]})

def server(l: Listener) -> IO(String):
  do IO<String>:
    x : Unit <- HTTP2.server.concurrent(~echo, l, CERT(), KEY())
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
    chan : Chan(String) <- IO.fork(String, server(l))
    +score : U32 <- peer_go(port)
    return score

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    +total : U32 <- run(b)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|4
