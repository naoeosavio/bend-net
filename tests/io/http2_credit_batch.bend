# io (httpx_h2_credit_batch): the receive side batches the credit pair
# of a DATA frame (task-063 phase 6b, RFC 9113 section 6.9.1).
#
# The peer is a raw H2 client and the server is HTTP2.server.concurrent.
# The peer uploads three DATA frames on stream 1: 16384 bytes, 16384
# bytes, then 1000 bytes with END_STREAM. The batch of one frame stays
# below x_wu_half(), so frame 1 answers no WINDOW_UPDATE at all. Frame 2
# brings the connection and the stream pending to 32768, so it answers
# the pair: the connection frame (sid 0) and the stream frame (sid 1),
# each with increment 32768, in one write. Frame 3 ends the body, so it
# answers the connection remainder alone (1000): the stream gets no
# credit because the peer sends no more DATA on it.
#
# Checks: the three WUs in order (sid and increment), the 200 head, the
# 33768-byte body, 3 WUs, 2 on the connection and 1 on the stream, and
# the two increment sums 33768 and 32768. Golden 8.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18791

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# The two full frames, the last frame of the body and the bytes of it.
def FULL() -> U32:
  16384

def LAST() -> U32:
  1000

def BODY_ALL() -> U32:
  33768

# x_wu_half(): the pending a frame needs to reach the flush.
def HALF() -> U32:
  32768

def WU_ALL() -> U32:
  3

# How many WUs each window takes: two on the connection (the pair and
# the remainder), one on the stream (the pair only).
def WU_CONN() -> U32:
  2

def WU_STREAM() -> U32:
  1

def CONN_SUM() -> U32:
  33768

def STREAM_SUM() -> U32:
  32768

def ACC_ORDER() -> U32:
  1

def ACC_HEAD() -> U32:
  2

def ACC_BODY() -> U32:
  4

def weigh(is_ok: Bool, +weight: U32) -> U32:
  match is_ok:
    case True{}:
      weight
    case False{}:
      0

def bit_ok(+acc: U32, +bit: U32) -> Bool:
  U32.is_eq(U32.and(acc, bit), bit)

def fill_go(+n: Nat, +b: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      fill_go(p, b, b <> acc)

def fill(+n: U32, +b: U32) -> List<&2, U32>:
  fill_go(U32.to_nat(n), b, Nil{})

def sock_of(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

# The sid and the increment each WU of the body must carry, in order.
def want_sid(+n: U32) -> U32:
  match n:
    case 1:
      1
    case _:
      0

def want_inc(+n: U32) -> U32:
  match n:
    case 0:
      HALF()
    case 1:
      HALF()
    case _:
      LAST()

def send_tail(sock: Socket) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
    b : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock, HTTP2.x_t_data(), 0, 1, fill(FULL(), 98))
    HTTP2.x_send_frame(sock_of(b), HTTP2.x_t_data(), HTTP2.x_f_end_stream(), 1, fill(LAST(), 99))

# The upload: two full frames, then the body frame with END_STREAM.
def send_all(sock: Socket) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
    a : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock, HTTP2.x_t_data(), 0, 1, fill(FULL(), 97))
    send_tail(sock_of(a))

# One WU, scored against its place in the sequence.
def wu_bit(+n: U32, +sid: U32, +payload: List<&2, U32>) -> U32:
  +ok_sid : Bool = U32.is_eq(sid, want_sid(n))
  +ok_inc : Bool = U32.is_eq(HTTP2.x_be32_rd(payload), want_inc(n))
  weigh(Bool.and(ok_sid, ok_inc), ACC_ORDER())

def head_bit_go(dec: Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab>) -> U32:
  match dec:
    case Fail{e}:
      0
    case Done{(+head, t)}:
      match head:
        case HTTP.Head{+status, +headers}:
          weigh(U32.is_eq(status, 200), ACC_HEAD())

def head_bit(+payload: List<&2, U32>) -> U32:
  head_bit_go(HTTP2.x_resp.decode(payload, HTTP2.x_tab.empty()))

# The answer body is the count the handler saw, as four bytes.
def body_bit(+flags: U32, +flen: U32, +payload: List<&2, U32>) -> U32:
  +end : Bool = U32.is_eq(U32.and(flags, HTTP2.x_f_end_stream()), HTTP2.x_f_end_stream())
  weigh(Bool.and(end, U32.is_eq(flen, 4)), weigh(U32.is_eq(HTTP2.x_be32_rd(payload), BODY_ALL()), ACC_BODY()))

def frame_bits(+n: U32, +typ: U32, +flags: U32, +flen: U32, +sid: U32, +payload: List<&2, U32>) -> U32:
  match typ:
    case 8:
      wu_bit(n, sid, payload)
    case 1:
      head_bit(payload)
    case 0:
      body_bit(flags, flen, payload)
    case _:
      0

# The count of WUs of one window: the connection (sid 0) or the stream.
def wu_conn(+typ: U32, +sid: U32) -> U32:
  match typ:
    case 8:
      weigh(U32.is_eq(sid, 0), 1)
    case _:
      0

def wu_stream(+typ: U32, +sid: U32) -> U32:
  match typ:
    case 8:
      weigh(U32.is_eq(sid, 1), 1)
    case _:
      0

def wu_conn_sum(+typ: U32, +sid: U32, +payload: List<&2, U32>) -> U32:
  match typ:
    case 8:
      weigh(U32.is_eq(sid, 0), HTTP2.x_be32_rd(payload))
    case _:
      0

def wu_stream_sum(+typ: U32, +sid: U32, +payload: List<&2, U32>) -> U32:
  match typ:
    case 8:
      weigh(U32.is_eq(sid, 1), HTTP2.x_be32_rd(payload))
    case _:
      0

def is_end(+typ: U32, +flags: U32) -> Bool:
  Bool.and(U32.is_eq(typ, 0), U32.is_eq(U32.and(flags, HTTP2.x_f_end_stream()), HTTP2.x_f_end_stream()))

def ph_of(done: Bool) -> U32:
  match done:
    case True{}:
      2
    case False{}:
      0

def peer_stop(s: Socket, +wus: U32, +wc: U32, +ws: U32, +wcs: U32, +wss: U32, +acc: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    +bits : U32 = U32.add(weigh(bit_ok(acc, ACC_ORDER()), 1), U32.add(weigh(bit_ok(acc, ACC_HEAD()), 1), weigh(bit_ok(acc, ACC_BODY()), 1)))
    +counts : U32 = U32.add(weigh(U32.is_eq(wus, WU_ALL()), 1), U32.add(weigh(U32.is_eq(wc, WU_CONN()), 1), weigh(U32.is_eq(ws, WU_STREAM()), 1)))
    +sums : U32 = U32.add(weigh(U32.is_eq(wcs, CONN_SUM()), 1), U32.add(weigh(U32.is_eq(wss, STREAM_SUM()), 1), 0))
    IO.pure(U32, (bits + U32.add(counts, sums) : U32))

# Phase 0 reads one frame, phase 1 scores it and picks the next phase, and
# phase 2 stops after the END_STREAM of the answer.
# shortcut: @unsafe, because the phases do not shrink one argument.
@unsafe
def peer_read(ph: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +wus: U32, +wc: U32, +ws: U32, +wcs: U32, +wss: U32, +acc: U32) ->
  IO(U32):
  match ph:
    case 0:
      (s0, g0) = got
      do IO<U32>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
        peer_read(1, got2, buf, wus, wc, ws, wcs, wss, acc)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          peer_stop(s1, wus, wc, ws, wcs, wss, acc)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
              +wus2 : U32 = (wus + weigh(U32.is_eq(typ, 8), 1) : U32)
              +wc2 : U32 = (wc + wu_conn(typ, sid) : U32)
              +ws2 : U32 = (ws + wu_stream(typ, sid) : U32)
              +wcs2 : U32 = (wcs + wu_conn_sum(typ, sid, payload) : U32)
              +wss2 : U32 = (wss + wu_stream_sum(typ, sid, payload) : U32)
              +acc2 : U32 = U32.or(acc, frame_bits(wus, typ, flags, flen, sid, payload))
              peer_read(ph_of(is_end(typ, flags)), (s1, HTTP.GotOk{frame, buf2}), buf2, wus2, wc2, ws2, wcs2, wss2, acc2)
    case _:
      (s2, g2) = got
      peer_stop(s2, wus, wc, ws, wcs, wss, acc)

def peer_go(sock: Socket) -> IO(U32):
  do IO<U32>:
    head : List<&2, U32> = HTTP2.client.on.req_block(HOST(), PORT(), "POST", "/batch", Nil{})
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock, HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 1, head)
    up : Socket & Result<&1, &1, U32 & String, Unit> <- send_all(sock_of(sent))
    peer_read(0, (sock_of(up), HTTP.GotErr{0, "next"}), Nil{}, 0, 0, 0, 0, 0, 0)

def peer_conn(conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, st) = value
      peer_go(sock)

def peer(port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTP2.client.connect_insecure(HOST(), port)
    peer_conn(conn)

# --- the server side: count the body it saw -------------------------

# The handler answers the body count it saw, as four bytes.
def count_h(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{method, path, headers, body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, HTTP.x_be32(HTTP.x_len32(body))})

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    x : Unit <- HTTP2.server.concurrent(~count_h, l, CERT(), KEY())
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
    +score : U32 <- peer(port)
    w : Unit <- IO.print(U32.show(score))
    z : Unit <- IO.die(Unit, 0, "")
    return score

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    run(b)

#|8
