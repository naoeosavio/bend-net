# io (httpx_h2_frame_big): one DATA frame of the largest size the module
# announces, larger than the 16384-byte read slice (task-063 phase 6b).
#
# The peer is a raw H2 client and the server is HTTP2.server.concurrent.
# The peer sends one DATA frame of 65535 bytes, the x_max_frame() cap and
# the whole default connection window, which the read loop assembles from
# five 16384-byte TLS reads, and the handler answers its byte count. The
# read accumulator appends the slices, and the append recursed on the
# buffer: a frame of 32777 bytes died with a machine stack overflow
# before the tail append landed.
#
# Checks: the 200 head, the 65535-byte body of the handler, and the
# connection WU of 65535 at the END_STREAM. Golden 3.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18794

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

def BODY() -> U32:
  65535

def ACC_WU() -> U32:
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

def sock_of_got(m: Socket & HTTP.Got) -> Socket:
  (s, g) = m
  s

# The connection WU of the whole body.
def wu_bit(+sid: U32, +payload: List<&2, U32>) -> U32:
  +is_conn : Bool = U32.is_eq(sid, 0)
  +is_inc : Bool = U32.is_eq(HTTP2.x_be32_rd(payload), BODY())
  weigh(Bool.and(is_conn, is_inc), ACC_WU())

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
  weigh(Bool.and(end, U32.is_eq(flen, 4)), weigh(U32.is_eq(HTTP2.x_be32_rd(payload), BODY()), ACC_BODY()))

def frame_bits(+typ: U32, +sd: U32, +flags: U32, +flen: U32, +payload: List<&2, U32>) -> U32:
  match typ:
    case 8:
      wu_bit(sd, payload)
    case 1:
      head_bit(payload)
    case 0:
      body_bit(flags, flen, payload)
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

def peer_stop(s: Socket, +acc: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    +bits : U32 = U32.add(weigh(bit_ok(acc, ACC_WU()), 1), U32.add(weigh(bit_ok(acc, ACC_HEAD()), 1), weigh(bit_ok(acc, ACC_BODY()), 1)))
    IO.pure(U32, bits)

# shortcut: @unsafe, because the phases do not shrink one argument.
@unsafe
def peer_read(ph: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +acc: U32) -> IO(U32):
  match ph:
    case 0:
      (s0, g0) = got
      do IO<U32>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
        peer_read(1, got2, buf, acc)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          peer_stop(s1, acc)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ, +flags, +sd, +flen, +payload}:
              +acc2 : U32 = U32.or(acc, frame_bits(typ, sd, flags, flen, payload))
              peer_read(ph_of(is_end(typ, flags)), (s1, HTTP.GotOk{frame, buf2}), buf2, acc2)
    case _:
      (s2, g2) = got
      peer_stop(s2, acc)

def peer_go(sock: Socket) -> IO(U32):
  do IO<U32>:
    head : List<&2, U32> = HTTP2.client.on.req_block(HOST(), PORT(), "POST", "/big", Nil{})
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock, HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 1, head)
    up : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock_of(sent), HTTP2.x_t_data(), HTTP2.x_f_end_stream(), 1, fill(BODY(), 97))
    peer_read(0, (sock_of(up), HTTP.GotErr{0, "next"}), Nil{}, 0)

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

#|3
