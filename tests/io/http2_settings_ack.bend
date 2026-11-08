# io (h2_settings_ack): the flow pump answers a SETTINGS that arrives
# while a send waits for credit (task-071 phase 2).
#
# The peer announces a stream window of WIN1 bytes and grants only the
# connection window, so the 4096-byte answer of stream 1 stops after WIN1.
# The peer then announces INITIAL_WINDOW_SIZE 0 and grants the rest of
# the body behind it. The window of stream 1 turns negative first, so the
# send cannot go on without the grant, and the pump must answer the
# SETTINGS before it reads the grant.
#
# The peer checks four things. The first frame after the mid-send
# SETTINGS is the ACK. Exactly two ACKs arrive before the body ends: one
# for the handshake SETTINGS and one for the mid-send SETTINGS. The body
# of stream 1 is whole. The last frame of stream 1 carries END_STREAM.
#
# Without the fix the pump stores the SETTINGS in the read seed and
# answers it only when the send ends, so the first frame after the
# SETTINGS is DATA and the ACK count is one.
#
# Checks: ACK first (1), two ACKs (2), the 4096-byte body (4), END_STREAM
# (8). Golden 15.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18856

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# The first stream window, and the body the handler answers. The body is
# larger than the window, so the send parks after the first frame.
def WIN1() -> U32:
  1024

def BODY() -> U32:
  4096

# The window the peer grants behind the mid-send SETTINGS: negative WIN1
# plus this grant is exactly the rest of the body.
def GRANT() -> U32:
  4096

def FUEL() -> Nat:
  64n

# Score bits, one per check.
def ACC_ACK_FIRST() -> U32:
  1

def ACC_ACK_TWO() -> U32:
  2

def ACC_BODY() -> U32:
  4

def ACC_END() -> U32:
  8

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# Sets one score bit when the check passes.
def set_bit(is_ok: Bool, +bit: U32, +acc: U32) -> U32:
  match is_ok:
    case True{}:
      U32.or(acc, bit)
    case False{}:
      acc

def sock_of(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

def is_end(+flags: U32) -> Bool:
  U32.is_eq(U32.and(flags, HTTP2.x_f_end_stream()), HTTP2.x_f_end_stream())

def is_ack(+flags: U32) -> Bool:
  U32.is_eq(U32.and(flags, HTTP2.x_f_ack()), HTTP2.x_f_ack())

def set_pay(+v: U32) -> List<&2, U32>:
  List.append(&2, U32, HTTP2.x_be16(4), HTTP.x_be32(v))

def fill_go(+n: Nat, +b: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      fill_go(p, b, b <> acc)

def srv_body() -> List<&2, U32>:
  fill_go(U32.to_nat(BODY()), 120, Nil{})

def srv(req: HTTP.Request) -> IO(HTTP.Response):
  IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, srv_body()})

def req_block() -> List<&2, U32>:
  HTTP2.x_block([HTTP.Hdr{":method", "GET"}, HTTP.Hdr{":path", "/body"}, HTTP.Hdr{":scheme", "https"}])

def send1(s: Socket, +typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) -> IO(Socket):
  do IO<Socket>:
    w : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, typ, flags, sid, pay)
    IO.pure(Socket, sock_of(w))

def send_pref(s: Socket) -> IO(Socket):
  do IO<Socket>:
    w : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(s, HTTP2.x_preface())
    IO.pure(Socket, sock_of(w))

# The peer answers a fresh SETTINGS of the server and ignores an ACK.
def ack_go(s: Socket, is_fresh: Bool) -> IO(Socket):
  match is_fresh:
    case True{}:
      send1(s, HTTP2.x_t_settings(), HTTP2.x_f_ack(), 0, Nil{})
    case False{}:
      IO.pure(Socket, s)

def ack_settings(s: Socket, +flags: U32) -> IO(Socket):
  ack_go(s, Bool.not(is_ack(flags)))

# The first frame after the mid-send SETTINGS: 1 when it is the ACK, 2
# when it is not, 0 while the mid-send SETTINGS is still to come.
def first_go(+ack: Bool, +first: U32) -> U32:
  match ack first:
    case True{} 0:
      1
    case False{} 0:
      2
    case _ _:
      first

def first_step(+ack: Bool, +mid: U32, +first: U32) -> U32:
  match mid:
    case 1:
      first_go(ack, first)
    case _:
      first

def acks_add(ack: Bool, +acks: U32) -> U32:
  U32.add(acks, b2u(ack))

# A DATA frame of stream 1 adds its payload to the stream total.
def total1(+t1: U32, +sid: U32, +pay: List<&2, U32>) -> U32:
  match sid:
    case 1:
      (t1 + HTTP.x_len32(pay) : U32)
    case _:
      t1

def done1_go(+done1: U32, +sid: U32, +flags: U32) -> U32:
  match sid:
    case 1:
      U32.max(done1, b2u(is_end(flags)))
    case _:
      done1

# The SETTINGS of the mid-send window and the grant behind it: the window
# of stream 1 turns negative, and the grant brings it back to the rest of
# the body. Both frames leave after the first DATA frame of the body,
# because that frame spends the whole first window.
def mid_go(s: Socket, is_mid: Bool) -> IO(Socket):
  match is_mid:
    case True{}:
      do IO<Socket>:
        s1 : Socket <- send1(s, HTTP2.x_t_settings(), 0, 0, set_pay(0))
        send1(s1, HTTP2.x_t_wu(), 0, 1, HTTP.x_be32(GRANT()))
    case False{}:
      IO.pure(Socket, s)

# Closes the connection and answers the score. The ACK count is read here,
# so the second bit proves exactly two ACKs before the body ends.
def peer_stop(s: Socket, +acks: U32, +acc: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    IO.pure(U32, set_bit(U32.is_eq(acks, 2), ACC_ACK_TWO(), acc))

# The peer loop: phase 0 reads, phase 1 dispatches. The state is the body
# total, the ACK count, the mid-send flag, the first-frame answer, the
# END_STREAM flag and the score.
@unsafe
def peer_loop(ph: U32, fuel: Nat, got: Socket & HTTP.Got, +buf: List<&2, U32>, +t1: U32, +acks: U32, +mid: U32, +first: U32, +done1: U32, +acc: U32) -> IO(U32):
  match ph:
    case 0:
      match fuel:
        case 0n:
          (s0, g0) = got
          peer_stop(s0, acks, acc)
        case 1n+f:
          (s1, g1) = got
          do IO<U32>:
            got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s1, buf)
            peer_disp(f, got2, buf, t1, acks, mid, first, done1, acc)
    case _:
      (s9, g9) = got
      peer_stop(s9, acks, acc)

@unsafe
def peer_disp(fuel: Nat, got: Socket & HTTP.Got, +buf: List<&2, U32>, +t1: U32, +acks: U32, +mid: U32, +first: U32, +done1: U32, +acc: U32) -> IO(U32):
  (s, g) = got
  match g:
    case HTTP.GotErr{code, msg}:
      peer_stop(s, acks, acc)
    case HTTP.GotOk{+frame, +buf2}:
      match frame:
        case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
          match typ:
            case 4:
              +ack : Bool = is_ack(flags)
              do IO<U32>:
                s2 : Socket <- ack_settings(s, flags)
                +acks2 : U32 = acks_add(ack, acks)
                +first2 : U32 = first_step(ack, mid, first)
                +acc2 : U32 = set_bit(Bool.and(U32.is_eq(mid, 1), Bool.and(U32.is_eq(first, 0), ack)), ACC_ACK_FIRST(), acc)
                peer_loop(0, fuel, (s2, HTTP.GotErr{0, "next"}), buf2, t1, acks2, mid, first2, done1, acc2)
            case 0:
              do IO<U32>:
                +t1b : U32 = total1(t1, sid, payload)
                +go_mid : Bool = Bool.and(U32.is_eq(mid, 0), U32.is_ge(t1b, WIN1()))
                s2 : Socket <- mid_go(s, go_mid)
                +mid2 : U32 = U32.max(mid, b2u(go_mid))
                +first2 : U32 = first_step(False{}, mid, first)
                +d1 : U32 = done1_go(done1, sid, flags)
                +acc2 : U32 = set_bit(U32.is_eq(t1b, BODY()), ACC_BODY(), acc)
                +acc3 : U32 = set_bit(Bool.and(U32.is_eq(d1, 1), U32.is_eq(t1b, BODY())), ACC_END(), acc2)
                peer_after(s2, U32.is_eq(d1, 1), acc3, fuel, buf2, t1b, acks, mid2, first2, d1)
            case _:
              +first2 : U32 = first_step(False{}, mid, first)
              peer_loop(0, fuel, (s, HTTP.GotErr{0, "next"}), buf2, t1, acks, mid, first2, done1, acc)

# The end of the body closes the run.
@unsafe
def peer_after(s: Socket, is_done: Bool, +acc: U32, fuel: Nat, +buf: List<&2, U32>, +t1: U32, +acks: U32, +mid: U32, +first: U32, +done1: U32) -> IO(U32):
  match is_done:
    case True{}:
      peer_stop(s, acks, acc)
    case False{}:
      peer_loop(0, fuel, (s, HTTP.GotErr{0, "next"}), buf, t1, acks, mid, first, done1, acc)

# The handshake: preface, a SETTINGS with WIN1, the connection credit and
# the request of stream 1.
def peer_go(sock: Socket) -> IO(U32):
  do IO<U32>:
    s1 : Socket <- send_pref(sock)
    s2 : Socket <- send1(s1, HTTP2.x_t_settings(), 0, 0, set_pay(WIN1()))
    s3 : Socket <- send1(s2, HTTP2.x_t_wu(), 0, 0, HTTP.x_be32(65535))
    s4 : Socket <- send1(s3, HTTP2.x_t_headers(), (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32), 1, req_block())
    peer_loop(0, FUEL(), (s4, HTTP.GotErr{0, "next"}), Nil{}, 0, 0, 0, 0, 0, 0)

def peer_conn(conn: Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      peer_go(sock)

def peer(port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_insecure(HOST(), port)
    peer_conn(conn)

def server_side(l: Listener) -> IO(Unit):
  do IO<Unit>:
    x : Unit <- HTTP2.server.concurrent(~srv, l, CERT(), KEY())
    IO.pure(Unit, Unit{})

def run(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l))
    +score : U32 <- peer(port)
    w : Unit <- IO.print(U32.show(score))
    z : Unit <- IO.die(Unit, 0, "")
    return score

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

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    run(b)

#|15
