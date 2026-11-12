# io (httpx_h2_flow_batch): a body past one split batch arrives whole
# (task-063 phase 12).
#
# The sender splits a body into one-MiB batches: 64 chunks of
# x_max_send() bytes, then the rest of the body as one chunk that the
# pump splits again when it reaches it. A 2 MiB body is two full batches,
# so the second batch is the rest chunk of the first, and the last batch
# ends on a chunk boundary.
#
# The peer is a raw H2 client. It reads the DATA frames of a BODY-byte
# response and grants back the credit of each frame, so the sender does
# not park for long.
#
# Checks: status 200, every DATA frame holds at most one chunk (the batch
# boundary must not make a frame wider), the bytes keep their index mod
# 256 order, the whole body arrives, and one END_STREAM on an empty frame.
# Golden 5.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18797

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# Response bytes: two full split batches.
def BODY() -> U32:
  2097152

# Acc bits, one per check.
def ACC_HEAD() -> U32:
  1

def ACC_CAP() -> U32:
  2

def ACC_ORDER() -> U32:
  4

def ACC_TOTAL() -> U32:
  8

def ACC_END() -> U32:
  16

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def bit_ok(+acc: U32, +bit: U32) -> Bool:
  U32.is_eq(U32.and(acc, bit), bit)

def weigh(is_ok: Bool, +weight: U32) -> U32:
  match is_ok:
    case True{}:
      weight
    case False{}:
      0

def sock_of(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

def sock_of_got(m: Socket & HTTP.Got) -> Socket:
  (s, g) = m
  s

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

# The payload bytes at the running index: byte j holds j mod 256.
def bytes_go(+pay: List<&2, U32>, +i: U32) -> Bool:
  match pay:
    case Nil{}:
      True{}
    case +h <> t:
      Bool.and(U32.is_eq(h, U32.and(i, 255)), bytes_go(t, (i + 1 : U32)))

def is_end(+typ: U32, +flags: U32) -> Bool:
  Bool.and(U32.is_eq(typ, 0), U32.is_eq(U32.and(flags, HTTP2.x_f_end_stream()), HTTP2.x_f_end_stream()))

# The bits one frame proves: the chunk cap, the byte order and the end of
# the stream on an empty frame.
def data_bits(+flags: U32, +pay: List<&2, U32>, +total: U32) -> U32:
  +len : U32 = HTTP.x_len32(pay)
  +cap : Bool = U32.is_le(len, HTTP2.x_max_send())
  +ord : Bool = bytes_go(pay, total)
  +end : Bool = Bool.and(is_end(0, flags), U32.is_eq(len, 0))
  U32.or(weigh(cap, ACC_CAP()), U32.or(weigh(ord, ACC_ORDER()), weigh(end, ACC_END())))

def acc_of(+acc: U32, +typ: U32, +flags: U32, +pay: List<&2, U32>, +total: U32) -> U32:
  match typ:
    case 0:
      U32.or(acc, data_bits(flags, pay, total))
    case 1:
      U32.or(acc, ACC_HEAD())
    case _:
      acc

# The body bytes a frame adds: the DATA payload, nothing else.
def total_of(+total: U32, +typ: U32, +pay: List<&2, U32>) -> U32:
  match typ:
    case 0:
      (total + HTTP.x_len32(pay) : U32)
    case _:
      total

# Gives the credit of one DATA frame back, so the pump keeps sending.
def peer_grant(s: Socket, +sid: U32, +len: U32) -> IO(Socket):
  do IO<Socket>:
    w1 : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_wu(), 0, 0, HTTP.x_be32(len))
    w2 : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock_of(w1), HTTP2.x_t_wu(), 0, sid, HTTP.x_be32(len))
    IO.pure(Socket, sock_of(w2))

def next_ph(done: Bool) -> U32:
  match done:
    case True{}:
      2
    case False{}:
      0

def peer_stop(s: Socket, +total: U32, +acc: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    +bits : U32 = U32.add(b2u(bit_ok(acc, ACC_HEAD())), U32.add(b2u(bit_ok(acc, ACC_CAP())), U32.add(b2u(bit_ok(acc, ACC_ORDER())), b2u(bit_ok(acc, ACC_END())))))
    +fin : U32 = b2u(U32.is_eq(total, BODY()))
    IO.pure(U32, U32.add(bits, fin))

# The read loop: score one frame, grant its credit, stop on END_STREAM.
@unsafe
def peer_read(ph: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +total: U32, +acc: U32) -> IO(U32):
  match ph:
    case 0:
      (s0, g0) = got
      do IO<U32>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
        peer_read(1, got2, buf, total, acc)
    case 1:
      (+s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          peer_stop(s1, total, acc)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
              match typ:
                case 0:
                  do IO<U32>:
                    s2 : Socket <- peer_grant(s1, sid, HTTP.x_len32(payload))
                    +bits : U32 = acc_of(acc, typ, flags, payload, total)
                    +t2 : U32 = total_of(total, typ, payload)
                    peer_read(next_ph(is_end(typ, flags)), (s2, HTTP.GotOk{frame, buf2}), buf2, t2, bits)
                case _:
                  do IO<U32>:
                    +bits : U32 = acc_of(acc, typ, flags, payload, total)
                    peer_read(0, (s1, HTTP.GotOk{frame, buf2}), buf2, total, bits)
    case _:
      (s9, g9) = got
      peer_stop(s9, total, acc)

def peer_go(sock: Socket) -> IO(U32):
  do IO<U32>:
    head : List<&2, U32> = HTTP2.client.req.block(HOST(), PORT(), "GET", "/big", Nil{})
    +flags : U32 = (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32)
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock, HTTP2.x_t_headers(), flags, 1, head)
    peer_read(0, (sock_of(sent), HTTP.GotErr{0, "next"}), Nil{}, 0, 0)

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

#|5
