# io (httpx_h2_settings_window): the send seeds the stream window from the
# peer SETTINGS INITIAL_WINDOW_SIZE (task-067 phase 8).
#
# The server loop reads a peer SETTINGS and carries the announced
# INITIAL_WINDOW_SIZE into the response send (task-067 phase 7). The cells
# of that phase measured the read with a node client, not with a test in
# the gate. The wire tests name the value at the leaf call, so they never
# reach the SETTINGS path.
#
# The peer here is raw. It dials over TLS and announces a window of WIN
# bytes on stream 1. It sends one request and credits both windows after
# each DATA frame. It answers one point per check:
#   * every DATA frame holds WIN bytes or less;
#   * the body bytes keep the index order;
#   * the body arrives whole;
#   * the stream ends.
# A send seeded with the RFC default puts the whole BODY in one frame, so
# the first check fails.
#
# Pure part: the shift of a second SETTINGS. The delta is the new value
# minus the value the peer announced before, never minus the RFC default.
# Five cases cover a grow, a shrink, a cut at zero, the same value and a
# payload without the setting.
#
# Golden 9.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18798

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# The stream window the peer announces, and the body it requests.
def WIN() -> U32:
  1024

def BODY() -> U32:
  4096

# Frames the peer reads before it stops: one DATA frame per window, plus
# the SETTINGS, the empty END_STREAM frame and a reserve.
def FUEL() -> Nat:
  32n

# Acc bits, one per wire check.
def ACC_LIMIT() -> U32:
  1

def ACC_ORDER() -> U32:
  2

def ACC_TOTAL() -> U32:
  4

def ACC_END() -> U32:
  8

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

# --- pure: the shift rule of a second SETTINGS ------------------------

# A SETTINGS payload that announces INITIAL_WINDOW_SIZE only.
def set_pay(+v: U32) -> List<&2, U32>:
  List.append(&2, U32, HTTP2.x_be16(4), HTTP.x_be32(v))

# Checks the new base and the new window of one SETTINGS step.
def pair_ok(p: U32 & U32, +want_base: U32, +want_sw: U32) -> U32:
  match p:
    case (b, w):
      U32.mul(b2u(U32.is_eq(b, want_base)), b2u(U32.is_eq(w, want_sw)))

def shift_ok(+pay: List<&2, U32>, +sw: U32, +cur: U32, +want_base: U32, +want_sw: U32) -> U32:
  pair_ok(HTTP2.x_settings.iw_step(pay, sw, cur), want_base, want_sw)

# Grow from 1024 to 4096, shrink from 4096 to 1024, a shrink past the
# window, the same value, and a payload without the setting.
def pure_score() -> U32:
  +grow : U32 = shift_ok(set_pay(4096), 1000, 1024, 4096, 4072)
  +shrink : U32 = shift_ok(set_pay(1024), 5000, 4096, 1024, 1928)
  +cut : U32 = shift_ok(set_pay(1024), 100, 4096, 1024, 0)
  +same : U32 = shift_ok(set_pay(1024), 777, 1024, 1024, 777)
  +none : U32 = shift_ok(Nil{}, 777, 1024, 1024, 777)
  U32.add(grow, U32.add(shrink, U32.add(cut, U32.add(same, none))))

# --- live: the raw peer ------------------------------------------------

def sock_of(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

def is_end(+flags: U32) -> Bool:
  U32.is_eq(U32.and(flags, HTTP2.x_f_end_stream()), HTTP2.x_f_end_stream())

# The phase of a DATA frame: 3 closes the stream, 4 credits the window.
def data_ph(done: Bool) -> U32:
  match done:
    case True{}:
      3
    case False{}:
      4

# The body holds byte j mod 256 at index j. A lost or moved byte then
# changes the order check.
@unsafe
def body_go(+n: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0:
      acc
    case _:
      body_go((n - 1 : U32), U32.and((n - 1 : U32), 255) <> acc)

def srv_body() -> List<&2, U32>:
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

def srv(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, srv_body()})

# The request block: a head needs :method and :path (RFC 9113 8.3.1).
def req_block() -> List<&2, U32>:
  HTTP2.x_block([HTTP.Hdr{":method", "GET"}, HTTP.Hdr{":path", "/body"}])

# Writes one frame and answers the socket.
def send1(s: Socket, +typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) -> IO(Socket):
  do IO<Socket>:
    w : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, typ, flags, sid, pay)
    IO.pure(Socket, sock_of(w))

# Writes the preface, which is not a frame.
def send_pref(s: Socket) -> IO(Socket):
  do IO<Socket>:
    w : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(s, HTTP2.x_preface())
    IO.pure(Socket, sock_of(w))

# Credits one consumed DATA frame on the stream and on the connection.
def credit(s: Socket, +len: U32) -> IO(Socket):
  do IO<Socket>:
    s1 : Socket <- send1(s, HTTP2.x_t_wu(), 0, 1, HTTP.x_be32(len))
    send1(s1, HTTP2.x_t_wu(), 0, 0, HTTP.x_be32(len))

# The bits one DATA frame proves. Only a frame with bytes proves the limit
# and the order. The empty END_STREAM frame closes the stream.
def data_bits(+acc: U32, +pay: List<&2, U32>, +total: U32) -> U32:
  +len : U32 = HTTP.x_len32(pay)
  +has : Bool = U32.is_gt(len, 0)
  +limit_ok : Bool = Bool.and(has, U32.is_le(len, WIN()))
  +order_ok : Bool = Bool.and(has, bytes_ok(pay, total))
  U32.or(acc, U32.or(weigh(limit_ok, ACC_LIMIT()), weigh(order_ok, ACC_ORDER())))

# The close that answers the wire score, four bits at most.
def wire_bits(+acc: U32, +total: U32) -> U32:
  +t : U32 = weigh(U32.is_eq(total, BODY()), ACC_TOTAL())
  U32.or(acc, t)

def wire_score(+all: U32) -> U32:
  U32.add(b2u(bit_ok(all, ACC_LIMIT())), U32.add(b2u(bit_ok(all, ACC_ORDER())), U32.add(b2u(bit_ok(all, ACC_TOTAL())), b2u(bit_ok(all, ACC_END())))))

def peer_stop(s: Socket, +acc: U32, +total: U32, done: Bool) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    +fin : U32 = weigh(done, ACC_END())
    +all : U32 = wire_bits(U32.or(acc, fin), total)
    IO.pure(U32, wire_score(all))

# The peer loop: phase 0 reads one frame, phase 1 dispatches it, phase 2
# reads a DATA frame, phase 3 closes the stream and phase 4 credits the
# window. One def holds the chain because Bend rejects mutual recursion.
# @unsafe: the phase ping-pong does not shrink a structural argument; FUEL
# bounds the loop.
@unsafe
def peer_loop(ph: U32, fuel: Nat, got: Socket & HTTP.Got, +buf: List<&2, U32>, +total: U32, acc: U32, +typ: U32, +flags: U32, +pay: List<&2, U32>) -> IO(U32):
  match ph:
    case 0:
      match fuel:
        case 0n:
          (s0, g0) = got
          peer_stop(s0, acc, total, False{})
        case 1n+f:
          (s0, g0) = got
          do IO<U32>:
            got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
            peer_loop(1, f, got2, buf, total, acc, 0, 0, Nil{})
    case 1:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          peer_stop(s1, acc, total, False{})
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ2, +flags2, +sid, +flen, +payload}:
              peer_loop(2, fuel, (s1, HTTP.GotErr{0, "next"}), buf2, total, acc, typ2, flags2, payload)
    case 2:
      match typ:
        case 0:
          +len : U32 = HTTP.x_len32(pay)
          +t2 : U32 = (total + len : U32)
          +acc2 : U32 = data_bits(acc, pay, total)
          peer_loop(data_ph(is_end(flags)), fuel, got, buf, t2, acc2, 0, flags, pay)
        case _:
          peer_loop(0, fuel, got, buf, total, acc, 0, 0, Nil{})
    case 3:
      (s3, g3) = got
      peer_stop(s3, acc, total, True{})
    case 4:
      (s4, g4) = got
      do IO<U32>:
        s5 : Socket <- credit(s4, HTTP.x_len32(pay))
        peer_loop(0, fuel, (s5, HTTP.GotErr{0, "next"}), buf, total, acc, 0, 0, Nil{})
    case _:
      (s9, g9) = got
      peer_stop(s9, acc, total, False{})

# The handshake order: preface, a SETTINGS with the announced window, then
# one request. The loop reads the SETTINGS before the HEADERS.
def peer_conn(conn: Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        s1 : Socket <- send_pref(sock)
        s2 : Socket <- send1(s1, HTTP2.x_t_settings(), 0, 0, set_pay(WIN()))
        s3 : Socket <- send1(s2, HTTP2.x_t_headers(), (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32), 1, req_block())
        peer_loop(0, FUEL(), (s3, HTTP.GotErr{0, "next"}), Nil{}, 0, 0, 0, 0, Nil{})

def peer_go(port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_insecure(HOST(), port)
    peer_conn(conn)

def server_side(l: Listener) -> IO(Unit):
  do IO<Unit>:
    x : Unit <- HTTP2.server.concurrent(~srv, l, CERT(), KEY())
    IO.pure(Unit, Unit{})

# The fork is left running: the process exits after the score.
def run(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l))
    +wire : U32 <- peer_go(port)
    +score : U32 = U32.add(wire, pure_score())
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

#|9
