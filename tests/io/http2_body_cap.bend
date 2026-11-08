# io (httpx_h2_body_cap): the buffered receive refuses a body past the
# cap (task-066 phase 2).
#
# The peer is a raw H2 client and the server is HTTP2.server.concurrent
# with a handler that answers the body length. Two connections:
#   - case A sends exactly x_max_body() bytes in 16384-byte DATA frames:
#     the cap does not refuse a body at the cap, the handler runs and
#     answers 200 with the 16777216-byte count;
#   - case B sends one byte more: the server answers RST_STREAM 8
#     (CANCEL), drops the stream and never calls the handler.
# The pure points pin the value of the cap and the two sides of its
# boundary, so a moved cap or a lost off-by-one fails without the wire.
#
# Checks: pure 3 (the cap value, at the cap accepted, one byte more
# refused), case A 2 (the 200 head, the body count), case B 1 (the reset
# code). Golden 6.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18789

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# The cap, the frame that carries it and the frame count that reaches it.
def CAP() -> U32:
  HTTP2.x_max_body()

def FRAME() -> U32:
  16384

def FRAMES() -> U32:
  U32.div(CAP(), FRAME())

# The one extra byte of case B, and the count the handler answers.
def ONE() -> U32:
  1

# Acc bits, one per check.
def ACC_HEAD() -> U32:
  1

def ACC_BODY() -> U32:
  2

def ACC_RST() -> U32:
  4

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def weigh(is_ok: Bool, +weight: U32) -> U32:
  match is_ok:
    case True{}:
      weight
    case False{}:
      0

def bit_ok(+acc: U32, +bit: U32) -> Bool:
  U32.is_eq(U32.and(acc, bit), bit)

# --- the pure boundary of the cap ------------------------------------

def pure_bits() -> U32:
  +cap_ok : Bool = U32.is_eq(CAP(), 16777216)
  +at_ok : Bool = Bool.not(HTTP2.x_body_over((CAP() - FRAME() : U32), FRAME()))
  +over_ok : Bool = HTTP2.x_body_over(CAP(), ONE())
  U32.add(weigh(cap_ok, 1), U32.add(weigh(at_ok, 1), weigh(over_ok, 1)))

# --- the raw peer ----------------------------------------------------

def fill_go(+n: Nat, +b: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      fill_go(p, b, b <> acc)

def fill(+n: U32, +b: U32) -> List<&2, U32>:
  fill_go(U32.to_nat(n), b, Nil{})

# One body frame, built once and reused: the sender copies it per write.
def chunk() -> List<&2, U32>:
  fill(FRAME(), 97)

def sock_of(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

def end_flags() -> U32:
  HTTP2.x_f_end_stream()

# Sends `left` body frames; the final one carries `flags_last`, which is
# END_STREAM for case A and zero for case B, where the one over-cap byte
# ends the stream.
@unsafe
def send_frames(+left: U32, +flags_last: U32, +chunk: List<&2, U32>, sock: Socket) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match left:
    case 0:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Done{Unit{}}))
    case _:
      do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
        +flags : U32 = U32.mul(HTTP2.x_b2u(U32.is_eq(left, 1)), flags_last)
        sent : Socket & Result<&1, &1, U32 & String, Unit> <-
          HTTP2.x_send_frame(sock, HTTP2.x_t_data(), flags, 1, chunk)
        send_frames((left - 1 : U32), flags_last, chunk, sock_of(sent))

# The one over-cap byte of case B, and the final END_STREAM on it. Case A
# sends nothing here: its last body frame already ended the stream.
def send_extra(mode: U32, sock: Socket) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match mode:
    case 0:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (sock, Done{Unit{}}))
    case _:
      HTTP2.x_send_frame(sock, HTTP2.x_t_data(), end_flags(), 1, [97])

# --- scoring ---------------------------------------------------------

def is_end(+typ: U32, +flags: U32) -> Bool:
  Bool.and(U32.is_eq(typ, 0), U32.is_eq(U32.and(flags, HTTP2.x_f_end_stream()), HTTP2.x_f_end_stream()))

# The answer head is a 200. A buffered response carries no body bytes
# other than the count, so the head is enough here.
def head_bit_go(dec: Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab>) -> U32:
  match dec:
    case Fail{e}:
      0
    case Done{(+head, t)}:
      match head:
        case HTTP.Head{+status, +headers}:
          weigh(U32.is_eq(status, 200), ACC_HEAD())

def head_bit(payload: List<&2, U32>) -> U32:
  head_bit_go(HTTP2.x_resp.decode(payload, HTTP2.x_tab.empty()))

# The count the handler saw, as four bytes, on the END_STREAM frame.
def body_bit(+flags: U32, +flen: U32, +payload: List<&2, U32>) -> U32:
  +end : Bool = U32.is_eq(U32.and(flags, HTTP2.x_f_end_stream()), HTTP2.x_f_end_stream())
  weigh(Bool.and(end, U32.is_eq(flen, 4)), weigh(U32.is_eq(HTTP2.x_be32_rd(payload), CAP()), ACC_BODY()))

# Case B: the server resets the stream with CANCEL and no handler answer.
def rst_bit(+typ: U32, +flags: U32, +flen: U32, +sid: U32, +payload: List<&2, U32>) -> U32:
  weigh(Bool.and(U32.is_eq(typ, 3), U32.is_eq(sid, 1)), weigh(U32.is_eq(HTTP2.x_be32_rd(payload), 8), ACC_RST()))

def frame_bits(mode: U32, +typ: U32, +flags: U32, +flen: U32, +sid: U32, +payload: List<&2, U32>) -> U32:
  match mode:
    case 0:
      match typ:
        case 1:
          head_bit(payload)
        case 0:
          body_bit(flags, flen, payload)
        case _:
          0
    case _:
      rst_bit(typ, flags, flen, sid, payload)

# 1 keeps reading, 2 stops: the stream ended or was reset.
def stop_of(mode: U32, +typ: U32, +flags: U32) -> Bool:
  match mode:
    case 0:
      is_end(typ, flags)
    case _:
      U32.is_eq(typ, 3)

def ph_of(done: Bool) -> U32:
  match done:
    case True{}:
      2
    case False{}:
      0

# Case A answers the head and the count; case B answers the reset code.
def stop_bits(mode: U32, +acc: U32) -> U32:
  match mode:
    case 0:
      U32.add(weigh(bit_ok(acc, ACC_HEAD()), 1), weigh(bit_ok(acc, ACC_BODY()), 1))
    case _:
      weigh(bit_ok(acc, ACC_RST()), 1)

def peer_stop(s: Socket, +mode: U32, +acc: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    IO.pure(U32, stop_bits(mode, acc))

@unsafe
def peer_read(+mode: U32, ph: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +acc: U32) -> IO(U32):
  match ph:
    case 0:
      (s0, g0) = got
      do IO<U32>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
        peer_read(mode, 1, got2, buf, acc)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          peer_stop(s1, mode, acc)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
              +acc2 : U32 = U32.or(acc, frame_bits(mode, typ, flags, flen, sid, payload))
              peer_read(mode, ph_of(stop_of(mode, typ, flags)), (s1, HTTP.GotOk{frame, buf2}), buf2, acc2)
    case _:
      (s2, g2) = got
      peer_stop(s2, mode, acc)

# One case: connect, send the head, send the body, score the answer.
def case_go(+mode: U32, sock: Socket) -> IO(U32):
  do IO<U32>:
    +head : List<&2, U32> = HTTP2.client.on.req_block(HOST(), PORT(), "POST", "/cap", Nil{})
    sent : Socket & Result<&1, &1, U32 & String, Unit> <-
      HTTP2.x_send_frame(sock, HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 1, head)
    +flags_last : U32 = U32.mul(U32.sub(1, mode), end_flags())
    up : Socket & Result<&1, &1, U32 & String, Unit> <-
      send_frames(FRAMES(), flags_last, chunk(), sock_of(sent))
    last : Socket & Result<&1, &1, U32 & String, Unit> <- send_extra(mode, sock_of(up))
    peer_read(mode, 0, (sock_of(last), HTTP.GotErr{0, "next"}), Nil{}, 0)

def peer_conn(mode: U32, conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, st) = value
      case_go(mode, sock)

def peer(mode: U32, r: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>) -> IO(U32):
  peer_conn(mode, r)

# Two connections in order: the at-cap body, then the over-cap byte.
def peer_two(+port: U32) -> IO(U32):
  do IO<U32>:
    c1 : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTP2.client.connect_insecure(HOST(), port)
    a : U32 <- peer(0, c1)
    c2 : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTP2.client.connect_insecure(HOST(), port)
    b : U32 <- peer(1, c2)
    IO.pure(U32, U32.add(a, b))

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
    +wire : U32 <- peer_two(port)
    +score : U32 = U32.add(pure_bits(), wire)
    w : Unit <- IO.print(U32.show(score))
    z : Unit <- IO.die(Unit, 0, "")
    return score

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    run(b)

#|6
