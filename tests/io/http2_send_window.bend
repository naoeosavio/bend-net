# io (httpx_h2_send_window): the one-frame send obeys the caller window
# (task-063 phase 7d and phase 11).
#
# A send takes the one-frame lane when the body fits one DATA frame
# (x_send_single). That lane wrote the whole body whatever credit the
# caller had left, then answered `cw - len`, which wraps below zero in
# U32. A caller with CW bytes left and a BODY-byte frame therefore sent a
# frame past the peer window, and the next send of the same connection
# started with a window of 2^32 - (BODY - CW). The lane now also needs
# `cw >= len`: a body past the window takes the pump path, which sends
# what the window allows and waits for credit.
#
# The peer is raw: it reads the preface, sends SETTINGS and GRANT bytes of
# connection credit, and scores the DATA frames. The sender dials with the
# library client and calls x_send_data_start with CW bytes of credit,
# which is less than the BODY bytes it holds.
#
# Checks: the first DATA frame holds exactly CW bytes and does not end the
# stream, every byte keeps its index mod 256 order, the last frame ends
# the stream with the whole body in, the send answers a window of zero and
# hands no read seed back. The peer answers one point per check it proves
# and the sender one point per check of its own. Golden 5.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18796

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# The body of the response, and the credit the sender has left.
def BODY() -> U32:
  200

def CW() -> U32:
  60

# The credit the peer grants after the first frame: the rest of the body.
def GRANT() -> U32:
  140

# Acc bits, one per check.
def ACC_FIRST() -> U32:
  1

def ACC_ORDER() -> U32:
  2

def ACC_END() -> U32:
  4

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

def list_nil(xs: List<&2, U32>) -> Bool:
  match xs:
    case Nil{}:
      True{}
    case h <> t:
      False{}

# The body: byte j holds j mod 256, so a lost or moved byte changes the
# order check.
@unsafe
def body_go(+n: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0:
      acc
    case _:
      body_go((n - 1 : U32), U32.and((n - 1 : U32), 255) <> acc)

def snd_body() -> List<&2, U32>:
  body_go(BODY(), Nil{})

# The payload bytes at the running index: byte j holds j mod 256.
def bytes_go(+pay: List<&2, U32>, +i: U32) -> Bool:
  match pay:
    case Nil{}:
      True{}
    case +h <> t:
      Bool.and(U32.is_eq(h, U32.and(i, 255)), bytes_go(t, (i + 1 : U32)))

def bytes_ok(+pay: List<&2, U32>, +i: U32) -> Bool:
  bytes_go(pay, i)

def is_end(+flags: U32) -> Bool:
  U32.is_eq(U32.and(flags, HTTP2.x_f_end_stream()), HTTP2.x_f_end_stream())

# --- the sender: dial and send BODY with CW bytes of credit -----------

# The seed the send hands back: the frames it read while it waited for
# credit. A SETTINGS and a WINDOW_UPDATE are acted on, not stashed, so an
# honest send hands nothing back.
def snd_end(sent: Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32) -> IO(U32):
  match sent:
    case (s, r, seed, cw):
      do IO<U32>:
        x : Unit <- TLS.tls_close(s)
        +cw_ok : Bool = U32.is_eq(cw, 0)
        IO.pure(U32, U32.add(b2u(cw_ok), b2u(list_nil(seed))))

def snd_go(sock: Socket) -> IO(U32):
  do IO<U32>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> & List<&2, U32> & U32 <-
      HTTP2.x_send_data_start(sock, 1, snd_body(), CW(), HTTP2.x_init_window(), HTTP2.x_init_window(), Nil{})
    snd_end(sent)

def snd_conn(conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, st) = value
      snd_go(sock)

def snd_side(port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <-
      HTTP2.client.connect_insecure(HOST(), port)
    snd_conn(conn)

# --- the peer: preface, SETTINGS plus GRANT, then the frame score -----

# The bits one DATA frame proves: the first frame is the credit the
# caller had and does not end the stream, its bytes keep the index order,
# and the last one ends the stream with the whole body in.
def data_bits(+flags: U32, +pay: List<&2, U32>, +total: U32) -> U32:
  +len : U32 = HTTP.x_len32(pay)
  +end : Bool = is_end(flags)
  +first : Bool = U32.is_eq(total, 0)
  +first_ok : Bool = Bool.and(U32.is_eq(len, CW()), Bool.not(end))
  +order_ok : Bool = bytes_ok(pay, total)
  +last_ok : Bool = Bool.and(end, U32.is_eq((total + len : U32), BODY()))
  +first_bits : U32 = weigh(Bool.and(first, first_ok), ACC_FIRST())
  U32.or(first_bits, U32.or(weigh(order_ok, ACC_ORDER()), weigh(last_ok, ACC_END())))

def acc_of_frame(+acc: U32, +typ: U32, +flags: U32, +pay: List<&2, U32>, +total: U32) -> U32:
  match typ:
    case 0:
      U32.or(acc, data_bits(flags, pay, total))
    case _:
      acc

# The body bytes a frame adds: the DATA payload, nothing else.
def total_of(+total: U32, +typ: U32, +pay: List<&2, U32>) -> U32:
  match typ:
    case 0:
      (total + HTTP.x_len32(pay) : U32)
    case _:
      total

# The stream ends on its own empty DATA frame, not on the last body byte:
# the pump sends END_STREAM as a separate frame (as in
# tests/io/http2_window_step.bend). The peer reads until that frame.
def frame_end(+typ: U32, +flags: U32) -> Bool:
  match typ:
    case 0:
      is_end(flags)
    case _:
      False{}

# 1 keeps reading, 2 stops: the stream ended.
def next_ph_go(done: Bool) -> U32:
  match done:
    case True{}:
      2
    case False{}:
      0

# A close that still answers a score of zero.
def close0(s: Socket) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    IO.pure(U32, 0)

def peer_stop(s: Socket, +acc: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    +bits : U32 = U32.add(b2u(bit_ok(acc, ACC_FIRST())), U32.add(b2u(bit_ok(acc, ACC_ORDER())), b2u(bit_ok(acc, ACC_END()))))
    IO.pure(U32, bits)

@unsafe
def peer_read(ph: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +total: U32, done: Bool, acc: U32) -> IO(U32):
  match ph:
    case 0:
      (s0, g0) = got
      do IO<U32>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
        peer_read(1, got2, buf, total, done, acc)
    case 1:
      (+s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          peer_stop(s1, acc)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
              do IO<U32>:
                +c2 : U32 = acc_of_frame(acc, typ, flags, payload, total)
                +t2 : U32 = total_of(total, typ, payload)
                +d2 : Bool = Bool.or(done, frame_end(typ, flags))
                peer_read(next_ph_go(d2), (s1, HTTP.GotOk{frame, buf2}), buf2, t2, d2, c2)
    case _:
      (s9, g9) = got
      peer_stop(s9, acc)

# The SETTINGS the peer sends after the preface, then the credit for the
# rest of the body. One write per frame: the sender parks after the first
# DATA frame and reads both here.
def peer_set(s: Socket, +rest: List<&2, U32>) -> IO(U32):
  do IO<U32>:
    w1 : Socket & Result<&1, &1, U32 & String, Unit> <-
      HTTP2.x_send_frame(s, HTTP2.x_t_settings(), 0, 0, HTTP2.x_settings_initial_pay())
    w2 : Socket & Result<&1, &1, U32 & String, Unit> <-
      HTTP2.x_send_frame(sock_of(w1), HTTP2.x_t_wu(), 0, 0, HTTP.x_be32(GRANT()))
    peer_read(0, (sock_of(w2), HTTP.GotErr{0, "next"}), rest, 0, False{}, 0)

# The client preface is not a frame: consume its 24 bytes first (mold
# tests/io/http2_goaway.bend; @unsafe for the same reason: the phase
# ping-pong does not shrink a structural argument).
@unsafe
def peer_pre(phase: U32, rs: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, ok: U32, short: Bool) -> IO(U32):
  match phase:
    case 0:
      (s0, r0) = rs
      match r0:
        case Fail{e}:
          close0(s0)
        case Done{+chunk}:
          +acc2 = List.append(&2, U32, acc, chunk)
          peer_pre(1, (s0, Done{chunk}), acc2, HTTP2.x_preface_ok(acc2), U32.is_lt(HTTP.x_len32(acc2), 24))
    case 1:
      (s1, r1) = rs
      match short:
        case True{}:
          do IO<U32>:
            r2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s1, 16384)
            peer_pre(0, r2, acc, 0, False{})
        case False{}:
          peer_pre(2, rs, acc, ok, short)
    case 2:
      (s2, r2) = rs
      match ok:
        case 1:
          peer_set(s2, HTTP.x_drop32(24, acc))
        case _:
          close0(s2)
    case _:
      (s9, r9) = rs
      close0(s9)

def peer_conn(r: Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        r1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
        peer_pre(0, r1, Nil{}, 0, False{})

def peer_acc(m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  (l, r) = m
  peer_conn(r)

def peer_go(l: Listener) -> IO(U32):
  do IO<U32>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, CERT(), KEY())
    peer_acc(m)

# The fork answers the sender bits; the peer waits here for them.
def maybe_u32(m: Maybe<&1, U32>) -> U32:
  match m:
    case None{}:
      0
    case Some{value}:
      value

def chan_bits(chan: Chan(U32)) -> IO(U32):
  do IO<U32>:
    m : Maybe<&1, U32> <- Chan.recv(U32, chan)
    IO.pure(U32, maybe_u32(m))

def run(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(U32) <- IO.fork(U32, snd_side(port))
    +peer_bits : U32 <- peer_go(l)
    +snd_bits : U32 <- chan_bits(chan)
    +score : U32 = U32.add(peer_bits, snd_bits)
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

#|5
