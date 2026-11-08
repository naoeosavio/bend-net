# io (httpx_h2_window_step): the sender when the peer window is smaller
# than one chunk (task-063 phase 4).
#
# The peer is a raw H2 client and the server is HTTP2.server.concurrent
# answering a BODY-byte response. The pump seeds both windows at 65535,
# so the first four DATA frames hold 16384, 16384, 16384 and 16383
# bytes. After that the peer grants STEP bytes on both windows for each
# frame it reads, and no frame may hold more than the credit it had: the
# pump takes a part of the head chunk and keeps the rest as the new head.
#
# Checks: status 200, every frame within the window, the four initial
# frame sizes, the byte order, the byte total, one END_STREAM. Golden 6.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18780

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# Response bytes: more than three initial windows, so the peer grants
# credit many times.
def BODY() -> U32:
  200000

def STEP() -> U32:
  4000

def INIT_WIN() -> U32:
  65535

# Acc bits, one per check.
def ACC_HEAD() -> U32:
  1

def ACC_WIN() -> U32:
  2

def ACC_INIT() -> U32:
  4

def ACC_ORDER() -> U32:
  8

def ACC_END() -> U32:
  16

def weigh(is_ok: Bool, +weight: U32) -> U32:
  match is_ok:
    case True{}:
      weight
    case False{}:
      0

def le_go(le: Bool, +a: U32, +b: U32) -> U32:
  match le:
    case True{}:
      a
    case False{}:
      b

def u32_min(+a: U32, +b: U32) -> U32:
  le_go(U32.is_le(a, b), a, b)

# The response body: byte j holds j mod 256, so a lost or moved byte
# changes the order check.
@unsafe
def body_go(+n: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0:
      acc
    case _:
      body_go((n - 1 : U32), U32.and((n - 1 : U32), 255) <> acc)

def big_body() -> List<&2, U32>:
  body_go(BODY(), Nil{})

def bit_ok(+acc: U32, +bit: U32) -> Bool:
  U32.is_eq(U32.and(acc, bit), bit)

# The payload bytes at the running index: byte j holds j mod 256.
def bytes_go(+pay: List<&2, U32>, +i: U32) -> Bool:
  match pay:
    case Nil{}:
      True{}
    case +h <> t:
      Bool.and(U32.is_eq(h, U32.and(i, 255)), bytes_go(t, (i + 1 : U32)))

def bytes_ok(+pay: List<&2, U32>, +i: U32) -> Bool:
  bytes_go(pay, i)

# RFC 9113 section 6.9.1: a frame never holds more than the credit the
# peer granted.
def win_go(in_credit: Bool, total: U32, allowed: U32, +len: U32) -> Bool:
  match in_credit:
    case False{}:
      False{}
    case True{}:
      U32.is_le(len, U32.sub(allowed, total))

def win_ok(+total: U32, +allowed: U32, +len: U32) -> Bool:
  win_go(U32.is_le(total, allowed), total, allowed, len)

# The first window sends full chunks up to the last slice, which is short
# because the seed window is not a multiple of the chunk.
def init_go(under: Bool, total: U32, +len: U32) -> Bool:
  match under:
    case False{}:
      True{}
    case True{}:
      U32.is_eq(len, u32_min(HTTP2.x_max_send(), U32.sub(INIT_WIN(), total)))

def init_ok(+total: U32, +len: U32) -> Bool:
  init_go(U32.is_lt(total, INIT_WIN()), total, len)

def end_ok(+flags: U32, +len: U32, total: U32) -> Bool:
  Bool.and(U32.is_eq(U32.and(flags, HTTP2.x_f_end_stream()), HTTP2.x_f_end_stream()), Bool.and(U32.is_eq(len, 0), U32.is_eq(total, BODY())))

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

# The bits one DATA frame proves: its window, its place in the first
# window, its byte order and its END_STREAM.
def data_bits(+flags: U32, +payload: List<&2, U32>, +total: U32, +allowed: U32) -> U32:
  +len : U32 = HTTP.x_len32(payload)
  U32.or(weigh(win_ok(total, allowed, len), ACC_WIN()), U32.or(weigh(init_ok(total, len), ACC_INIT()), U32.or(weigh(bytes_ok(payload, total), ACC_ORDER()), weigh(end_ok(flags, len, total), ACC_END()))))

def acc_of_frame(+acc: U32, +typ: U32, +flags: U32, +payload: List<&2, U32>, total: U32, allowed: U32) -> U32:
  match typ:
    case 1:
      U32.or(acc, head_bit(payload))
    case 0:
      U32.or(acc, data_bits(flags, payload, total, allowed))
    case _:
      acc

# The body bytes a frame adds: the DATA payload, nothing else.
def total_of(+total: U32, +typ: U32, +payload: List<&2, U32>) -> U32:
  match typ:
    case 0:
      (total + HTTP.x_len32(payload) : U32)
    case _:
      total

def is_end(+typ: U32, +flags: U32) -> Bool:
  Bool.and(U32.is_eq(typ, 0), U32.is_eq(U32.and(flags, HTTP2.x_f_end_stream()), HTTP2.x_f_end_stream()))

# The peer grants credit when the pump has spent what it had, and stops
# granting once the body is in.
def next_grant(+total: U32, +allowed: U32) -> Bool:
  Bool.and(U32.is_eq(total, allowed), U32.is_lt(total, BODY()))

# The window after this turn: STEP more when the peer grants.
def step_of(grant: Bool, +allowed: U32) -> U32:
  match grant:
    case True{}:
      (allowed + STEP() : U32)
    case False{}:
      allowed

def sock_of(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

def sock_of_got(m: Socket & HTTP.Got) -> Socket:
  (s, g) = m
  s

# STEP bytes on the connection and STEP on the stream, the way a small
# reader walks a large answer.
def peer_grant(got: Socket & HTTP.Got, +buf: List<&2, U32>) -> IO(Socket & HTTP.Got):
  (s, g) = got
  do IO<Socket & HTTP.Got>:
    w1 : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_wu(), 0, 0, HTTP.x_be32(STEP()))
    w2 : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock_of(w1), HTTP2.x_t_wu(), 0, 1, HTTP.x_be32(STEP()))
    IO.pure(Socket & HTTP.Got, (sock_of(w2), g))

def peer_credit(grant: Bool, got: Socket & HTTP.Got, +buf: List<&2, U32>) -> IO(Socket & HTTP.Got):
  match grant:
    case False{}:
      IO.pure(Socket & HTTP.Got, got)
    case True{}:
      peer_grant(got, buf)

def peer_stop(s: Socket, +total: U32, +acc: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    +bits : U32 = U32.add(weigh(bit_ok(acc, ACC_HEAD()), 1), U32.add(weigh(bit_ok(acc, ACC_WIN()), 1), U32.add(weigh(bit_ok(acc, ACC_INIT()), 1), U32.add(weigh(bit_ok(acc, ACC_ORDER()), 1), weigh(bit_ok(acc, ACC_END()), 1)))))
    IO.pure(U32, (bits + weigh(U32.is_eq(total, BODY()), 1) : U32))

# The phase after a frame: 2 stops the loop on END_STREAM, 0 grants and
# reads the next one.
def ph_of(done: Bool) -> U32:
  match done:
    case True{}:
      2
    case False{}:
      0

# Phase 0 grants when the pump has spent its credit and reads one frame;
# phase 1 scores that frame and picks the next phase; phase 2 stops. The
# loop ends on the END_STREAM frame, and a pump that sends nothing stops
# on the gate timeout.
# shortcut: @unsafe, because the phases do not shrink one argument.
@unsafe
def peer_read(ph: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +total: U32, +allowed: U32, +grant: Bool, +acc: U32) ->
  IO(U32):
  match ph:
    case 0:
      (s1, g1) = got
      +allowed2 : U32 = step_of(grant, allowed)
      do IO<U32>:
        w : Socket & HTTP.Got <- peer_credit(grant, (s1, g1), buf)
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(sock_of_got(w), buf)
        peer_read(1, got2, buf, total, allowed2, False{}, acc)
    case 1:
      (s2, g2) = got
      match g2:
        case HTTP.GotErr{code, msg}:
          peer_stop(s2, total, acc)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ, +flags, +sid,+flen, +payload}:
              +total2 : U32 = total_of(total, typ, payload)
              +acc2 : U32 = acc_of_frame(acc, typ, flags, payload, total, allowed)
              peer_read(ph_of(is_end(typ, flags)), (s2, HTTP.GotOk{frame, buf2}), buf2, total2, allowed, next_grant(total2, allowed), acc2)
    case _:
      (s3, g3) = got
      peer_stop(s3, total, acc)

def peer_go(sock: Socket) -> IO(U32):
  do IO<U32>:
    head : List<&2, U32> = HTTP2.client.on.req_block(HOST(), PORT(), "GET", "/big", Nil{})
    +flags : U32 = (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32)
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock, HTTP2.x_t_headers(), flags, 1, head)
    peer_read(0, (sock_of(sent), HTTP.GotErr{0, "next"}), Nil{}, 0, INIT_WIN(), False{}, 0)

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

# --- the server side: one buffered answer of BODY bytes --------------

def big(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{method, path, headers, body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, big_body()})

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    x : Unit <- HTTP2.server.concurrent(~big, l, CERT(), KEY())
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

#|6
