# io (httpx_h2_stray_data): a DATA frame of a stream the ledger does not
# hold must not close the connection (task-062 phase 2, finding 2).
#
# The server is HTTPX.server.concurrent with an echo handler, so the
# buffered lane parks the request of stream 1 and answers it on its DATA.
# The peer sends, in order: HEADERS(1, no END_STREAM), DATA(3, END_STREAM)
# -- a stream that was never opened -- and DATA(1, END_STREAM).
# The server must credit the connection window of the stray five bytes
# (WINDOW_UPDATE, sid 0, increment 5), read on, and answer stream 1 with
# 200. Before the fix the buffered act table answered 4 for a DATA with no
# slot, no arm matched 4, and the connection closed: stream 1 never got an
# answer.
#
# Score: the credit plus the answer, golden 2.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18548

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# The stray stream and its five bytes, then the real one.
def STRAY_SID() -> U32:
  3

def REAL_SID() -> U32:
  1

def STRAY_LEN() -> U32:
  5

# Acc bits: the credit, the answer.
def ACC_WU() -> U32:
  1

def ACC_RESP() -> U32:
  2

# Frames the peer reads before it gives up.
def FUEL() -> Nat:
  16n

def hello() -> String:
  "hello"

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# A send becomes the seed of the read loop: a failed write keeps the code.
def sent_seed(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & HTTP.Got:
  (s, r) = m
  match r:
    case Fail{(code, msg)}:
      (s, HTTP.GotErr{code, msg})
    case Done{u}:
      (s, HTTP.GotErr{0, "next"})

def acc_full() -> U32:
  (ACC_WU() + ACC_RESP() : U32)

def is_full(+acc: U32) -> Bool:
  U32.is_eq(U32.and(acc, acc_full()), acc_full())

# The phase after a frame: 2 stops, 0 reads on.
def next_phase(is_done: Bool) -> U32:
  match is_done:
    case True{}:
      2
    case False{}:
      0

# One point per bit: the credit and the answer, whatever repeats them.
def score_of(+acc: U32) -> U32:
  U32.add(b2u(U32.is_eq(U32.and(acc, ACC_WU()), ACC_WU())), b2u(U32.is_eq(U32.and(acc, ACC_RESP()), ACC_RESP())))

# The connection-level credit of the stray bytes: WINDOW_UPDATE, sid 0,
# increment STRAY_LEN.
def wu_ok(+sid: U32, +payload: List<&2, U32>) -> U32:
  U32.mul(b2u(U32.is_eq(sid, 0)), U32.mul(b2u(U32.is_eq(HTTP.x_len32(payload), 4)), b2u(U32.is_eq(HTTP2.x_be32_rd(payload), STRAY_LEN()))))

# A HEADERS answer of REAL_SID with :status 200.
def resp_ok(dec: Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab>) -> U32:
  match dec:
    case Fail{e}:
      0
    case Done{value}:
      match value:
        case (head, tab):
          match head:
            case HTTP.Head{+status, +headers}:
              b2u(U32.is_eq(status, 200))

def acc_add(+acc: U32, +typ: U32, +sid: U32, +payload: List<&2, U32>) -> U32:
  match typ:
    case 8:
      (acc + wu_ok(sid, payload) : U32)
    case 1:
      (acc + resp_ok(HTTP2.x_resp.decode(payload, HTTP2.x_tab.empty())) : U32)
    case _:
      acc

def stop_at(got: Socket & HTTP.Got, +acc: U32) -> Socket & U32:
  (s, g) = got
  (s, score_of(acc))

def peer_read(fuel: Nat, ph: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +acc: U32) ->
  IO(Socket & U32):
  match fuel:
    case 0n:
      IO.pure(Socket & U32, stop_at(got, acc))
    case 1n+p:
      match ph:
        case 0:
          (s0, g0) = got
          do IO<Socket & U32>:
            got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
            peer_read(p, 1, got2, buf, acc)
        case 1:
          (s1, g1) = got
          match g1:
            case HTTP.GotErr{code, msg}:
              IO.pure(Socket & U32, stop_at(got, acc))
            case HTTP.GotOk{+frame, +buf2}:
              match frame:
                case HTTP.Frame{+typ, +flags, +sid, +payload}:
                  +acc2 : U32 = U32.or(acc, acc_add(acc, typ, sid, payload))
                  peer_read(p, next_phase(is_full(acc2)), (s1, HTTP.GotOk{frame, buf2}), buf2, acc2)
        case _:
          (s9, g9) = got
          IO.pure(Socket & U32, stop_at(got, acc))

def peer_done(m: Socket & U32) -> IO(U32):
  (s, +score) = m
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    return score

def peer_go(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  (s, r) = m
  match r:
    case Fail{e}:
      peer_done((s, 0))
    case Done{u}:
      do IO<U32>:
        got : Socket & HTTP.Got <- HTTP2.x_read_frame(s, Nil{})
        res : Socket & U32 <- peer_read(FUEL(), 1, got, Nil{}, 0)
        peer_done(res)

# The real stream's body, after the stray frame was answered with credit.
def real_sent(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  (s, r) = m
  match r:
    case Fail{e}:
      peer_done((s, 0))
    case Done{u}:
      do IO<U32>:
        body : List<&2, U32> = HTTP.x_str_bytes(hello())
        sent : Socket & Result<&1, &1, U32 & String, Unit> <-
          HTTP2.x_send_frame(s, HTTP2.x_t_data(), HTTP2.x_f_end_stream(), REAL_SID(), body)
        peer_go(sent)

def stray_sent(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  (s, r) = m
  match r:
    case Fail{e}:
      peer_done((s, 0))
    case Done{u}:
      do IO<U32>:
        body : List<&2, U32> = HTTP.x_str_bytes(hello())
        sent : Socket & Result<&1, &1, U32 & String, Unit> <-
          HTTP2.x_send_frame(s, HTTP2.x_t_data(), HTTP2.x_f_end_stream(), STRAY_SID(), body)
        real_sent(sent)

def peer_start(sock: Socket) -> IO(U32):
  do IO<U32>:
    head : List<&2, U32> = HTTP2.client.on.req_block(HOST(), PORT(), "GET", "/stray", Nil{})
    sent : Socket & Result<&1, &1, U32 & String, Unit> <-
      HTTP2.x_send_frame(sock, HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), REAL_SID(), head)
    stray_sent(sent)

def peer_conn(conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, st) = value
      peer_start(sock)

def peer(+port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTPX.client.connect_insecure(HOST(), port)
    peer_conn(conn)

def echo(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, body})

def server(l: Listener) -> IO(String):
  do IO<String>:
    x : Unit <- HTTPX.server.concurrent(~echo, l, CERT(), KEY())
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
    +score : U32 <- peer(port)
    return score

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    +total : U32 <- run(b)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|2
