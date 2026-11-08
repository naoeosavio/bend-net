# io (http2_window_debt): a SETTINGS that lowers INITIAL_WINDOW_SIZE
# leaves a negative stream window, and the sender waits for the credit
# that pays the debt (task-068 phase 8).
#
# RFC 9113 section 6.9.2: a new INITIAL_WINDOW_SIZE moves every open stream
# window by the difference of the two values, and the window can become
# negative. A sender must not send a flow-controlled frame until a
# WINDOW_UPDATE makes the window positive. The old code clamped the window
# to zero, so the first WINDOW_UPDATE gave its whole credit and the sender
# overran the peer window.
#
# Two scenarios hold one shape:
#   * A: the library server sends a BODY-byte response and the raw client
#     lowers the value from WIN0 to WIN1 after the first window is spent;
#   * B: the library client uploads a BODY-byte request and the raw server
#     does the same.
# In both, the peer then grants GRANT bytes, which pays the debt of
# WIN0 - WIN1 bytes and leaves WIN1. A PING follows the grant: the sender
# answers it only after it stalls, so the DATA bytes that arrive before the
# answer are the bytes the new window allowed. They must be WIN1 at most;
# the clamp sends GRANT bytes.
#
# Each scenario scores three points: the bounded burst, the whole body and
# the end of the stream. The peer prints one line for each point.
# Golden 6.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18941

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# The window both peers start with, the value the mid-send SETTINGS
# announces, the body of each scenario and the credit that pays the debt.
def WIN0() -> U32:
  65535

def WIN1() -> U32:
  1024

def BODY() -> U32:
  200000

def GRANT() -> U32:
  65535

# The client preface is 24 bytes of magic and is not a frame.
def PREFACE_LEN() -> U32:
  24

# Frames the peer reads before it stops: the SETTINGS exchange, the frames
# of the body and a reserve.
def FUEL() -> Nat:
  512n

# The stage of the peer: 0 before the trigger, 1 while it measures the
# burst the new window allows, and 2 after the grant that pays the rest.
def STAGE_PRE() -> U32:
  0

def STAGE_POST() -> U32:
  1

def STAGE_GRANT() -> U32:
  2

# The verdict of the burst: 1 when the window bounds it, 2 when it
# overruns the window.
def BOUND_OK() -> U32:
  1

def BOUND_BAD() -> U32:
  2

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def x_bound(ok: Bool) -> U32:
  match ok:
    case True{}:
      BOUND_OK()
    case False{}:
      BOUND_BAD()

def bound_of(+n: U32) -> U32:
  x_bound(Bool.and(U32.is_gt(n, 0), U32.is_le(n, WIN1())))

# True from the frame that spends the first window on.
def is_spent(+total: U32) -> Bool:
  U32.is_ge(total, WIN0())

# Bytes of one body. The peer counts them and never reads a value.
def body_go(fuel: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match fuel:
    case 0n:
      acc
    case 1n+f:
      body_go(f, 97 <> acc)

def body() -> List<&2, U32>:
  body_go(U32.to_nat(BODY()), Nil{})

# A PING payload. The answer echoes it, so the peer reads it back.
def PING_PAY() -> List<&2, U32>:
  HTTP.x_be32(20261104)

# --- the raw peer, shared by both scenarios ---------------------------

def sock_of(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

# Writes one frame and answers the socket.
def send1(s: Socket, +typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) -> IO(Socket):
  do IO<Socket>:
    w : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, typ, flags, sid, pay)
    IO.pure(Socket, sock_of(w))

# A SETTINGS payload with INITIAL_WINDOW_SIZE only.
def set_pay(+v: U32) -> List<&2, U32>:
  List.append(&2, U32, HTTP2.x_be16(4), HTTP.x_be32(v))

# The two WINDOW_UPDATE frames of one grant: the stream and the connection.
def peer_grant(s: Socket) -> IO(Socket):
  do IO<Socket>:
    s1 : Socket <- send1(s, HTTP2.x_t_wu(), 0, 1, HTTP.x_be32(GRANT()))
    send1(s1, HTTP2.x_t_wu(), 0, 0, HTTP.x_be32(GRANT()))

# The mid-send lowering, the grant that pays the debt it leaves, and the
# PING whose answer marks the end of the burst.
def peer_trigger(s: Socket) -> IO(Socket):
  do IO<Socket>:
    s1 : Socket <- send1(s, HTTP2.x_t_settings(), 0, 0, set_pay(WIN1()))
    s2 : Socket <- peer_grant(s1)
    send1(s2, HTTP2.x_t_ping(), 0, 0, PING_PAY())

def peer_answer(s: Socket) -> IO(Socket):
  do IO<Socket>:
    w : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_headers(), (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32), 1, HTTP2.x_block([HTTP.Hdr{":status", "200"}]))
    IO.pure(Socket, sock_of(w))

# The answer the raw server owes the client. The raw client owes none.
def peer_close(is_server: Bool, s: Socket) -> IO(Socket):
  match is_server:
    case True{}:
      peer_answer(s)
    case False{}:
      IO.pure(Socket, s)

def peer_ack(s: Socket) -> IO(Socket):
  send1(s, HTTP2.x_t_settings(), HTTP2.x_f_ack(), 0, Nil{})

# The action of one frame: 1 acknowledges a fresh SETTINGS, 2 counts a
# DATA frame, 3 closes the burst on our PING answer and 0 ignores the
# frame.
def peer_act_set(fresh: Bool) -> U32:
  match fresh:
    case True{}:
      1
    case False{}:
      0

def is_ack_flag(+flags: U32) -> Bool:
  U32.is_eq(U32.and(flags, HTTP2.x_f_ack()), 1)

def peer_act_ping(is_ack: Bool) -> U32:
  match is_ack:
    case True{}:
      3
    case False{}:
      0

def peer_act(+typ: U32, +flags: U32) -> U32:
  match typ:
    case 4:
      peer_act_set(U32.is_eq(U32.and(flags, HTTP2.x_f_ack()), 0))
    case 0:
      2
    case 6:
      peer_act_ping(is_ack_flag(flags))
    case _:
      0

def end_flag(+flags: U32) -> U32:
  U32.and(flags, HTTP2.x_f_end_stream())

# The close: three checks, one line each, and the count.
def peer_bit(name: String, +bit: U32) -> IO(Unit):
  IO.print(String.append(name, String.append(" ", U32.show(bit))))

def peer_finish(+tag: String, s: Socket, +total: U32, +bounded: U32, +ends: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    +bounded_bit : U32 = b2u(U32.is_eq(bounded, BOUND_OK()))
    +body_bit : U32 = b2u(U32.is_eq(total, BODY()))
    +end_bit : U32 = b2u(U32.is_eq(ends, 1))
    p1 : Unit <- peer_bit(String.append(tag, ".bounded"), bounded_bit)
    p2 : Unit <- peer_bit(String.append(tag, ".body"), body_bit)
    p3 : Unit <- peer_bit(String.append(tag, ".end"), end_bit)
    IO.pure(U32, U32.add(bounded_bit, U32.add(body_bit, end_bit)))

# The close of the burst: the PING answer arrived, so the sender stalled.
# The bytes behind the grant are the burst the new window allowed.
@unsafe
def peer_pinged(stage: U32, fuel: Nat, +is_server: Bool, s: Socket, +buf: List<&2, U32>, +total: U32, +burst: U32, +ends: U32) -> IO(U32):
  match stage:
    case 1:
      do IO<U32>:
        s2 : Socket <- peer_grant(s)
        peer(0, fuel, is_server, (s2, HTTP.GotErr{0, "next"}), buf, total, bound_of(burst), ends, STAGE_GRANT(), 0, 0, 0, Nil{}, 0, 4)
    case _:
      peer(0, fuel, is_server, (s, HTTP.GotErr{0, "next"}), buf, total, 0, ends, stage, 0, 0, 0, Nil{}, 0, 4)

# After a DATA frame that is not the end: trigger the lowering, add the
# frame to the burst, then grant what the body has left.
@unsafe
def peer_stage(stage: U32, spent: Bool, fuel: Nat, +is_server: Bool, s: Socket, +buf: List<&2, U32>, +total: U32, +burst: U32, +ends: U32, +len: U32) -> IO(U32):
  match stage spent:
    case 0 True{}:
      do IO<U32>:
        s2 : Socket <- peer_trigger(s)
        peer(0, fuel, is_server, (s2, HTTP.GotErr{0, "next"}), buf, total, 0, ends, STAGE_POST(), 0, 0, 0, Nil{}, 0, 4)
    case 0 False{}:
      peer(0, fuel, is_server, (s, HTTP.GotErr{0, "next"}), buf, total, burst, ends, STAGE_PRE(), 0, 0, 0, Nil{}, 0, 4)
    case 1 _:
      peer(0, fuel, is_server, (s, HTTP.GotErr{0, "next"}), buf, total, (burst + len : U32), ends, STAGE_POST(), 0, 0, 0, Nil{}, 0, 4)
    case _ _:
      do IO<U32>:
        s2 : Socket <- peer_grant(s)
        peer(0, fuel, is_server, (s2, HTTP.GotErr{0, "next"}), buf, total, burst, ends, STAGE_GRANT(), 0, 0, 0, Nil{}, 0, 4)

# After a DATA frame: the end closes, any other frame takes the stage step.
@unsafe
def peer_data(end: U32, fuel: Nat, +is_server: Bool, s: Socket, +buf: List<&2, U32>, +total: U32, +burst: U32, +ends: U32, +stage: U32, +len: U32) -> IO(U32):
  match end:
    case 1:
      do IO<U32>:
        s2 : Socket <- peer_close(is_server, s)
        peer_finish(tag_of(is_server), s2, total, burst, (ends + 1 : U32))
    case _:
      peer_stage(stage, is_spent(total), fuel, is_server, s, buf, total, burst, ends, len)

def tag_of(is_server: Bool) -> String:
  match is_server:
    case True{}:
      "server"
    case False{}:
      "client"

# The raw peer: phase 0 reads one frame, phase 1 keeps it and phase 2 acts
# on it. One def holds the chain because Bend rejects mutual recursion.
# @unsafe: the phase ping-pong does not shrink a structural argument; FUEL
# bounds the loop.
@unsafe
def peer(ph: U32, fuel: Nat, +is_server: Bool, got: Socket & HTTP.Got, +buf: List<&2, U32>, +total: U32, +bounded: U32, +ends: U32, +stage: U32, +typ: U32, +flags: U32, +sid: U32, +payload: List<&2, U32>, +end: U32, act: U32) -> IO(U32):
  match ph:
    case 0:
      match fuel:
        case 0n:
          (s0, g0) = got
          peer_finish(tag_of(is_server), s0, total, bounded, ends)
        case 1n+f:
          (s0, g0) = got
          do IO<U32>:
            got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
            peer(1, f, is_server, got2, buf, total, bounded, ends, stage, 0, 0, 0, Nil{}, 0, 4)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          peer_finish(tag_of(is_server), s1, total, bounded, ends)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ2, +flags2, +sid2, +flen2, +payload2}:
              peer(2, fuel, is_server, (s1, HTTP.GotOk{frame, buf2}), buf2, total, bounded, ends, stage, typ2, flags2, sid2, payload2, end_flag(flags2), peer_act(typ2, flags2))
    case 2:
      match act:
        case 1:
          do IO<U32>:
            s2 : Socket <- peer_ack(s_of(got))
            peer(0, fuel, is_server, (s2, HTTP.GotErr{0, "next"}), buf, total, bounded, ends, stage, 0, 0, 0, Nil{}, 0, 4)
        case 2:
          +len : U32 = HTTP.x_len32(payload)
          +t2 : U32 = (total + len : U32)
          peer_data(end, fuel, is_server, s_of(got), buf, t2, bounded, ends, stage, len)
        case 3:
          peer_pinged(stage, fuel, is_server, s_of(got), buf, total, bounded, ends)
        case _:
          peer(0, fuel, is_server, got, buf, total, bounded, ends, stage, 0, 0, 0, Nil{}, 0, 4)
    case _:
      (s9, g9) = got
      peer_finish(tag_of(is_server), s9, total, bounded, ends)

def s_of(got: Socket & HTTP.Got) -> Socket:
  (s, g) = got
  s

# The client preface is 24 bytes and is not a frame. Read until it is
# whole and answer the socket with the bytes behind it.
@unsafe
def peer_app(r: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>) -> Socket & List<&2, U32>:
  match r:
    case (s, Fail{e}):
      (s, acc)
    case (s, Done{+chunk}):
      (s, List.append(&2, U32, acc, chunk))

def is_pre_whole(+acc: List<&2, U32>) -> Bool:
  U32.is_ge(HTTP.x_len32(acc), PREFACE_LEN())

@unsafe
def peer_pre(fuel: Nat, got: Socket & List<&2, U32>) -> IO(Socket & List<&2, U32>):
  match got:
    case (s, +acc):
      peer_pre_go(fuel, is_pre_whole(acc), s, acc)

@unsafe
def peer_pre_go(fuel: Nat, whole: Bool, s: Socket, +acc: List<&2, U32>) -> IO(Socket & List<&2, U32>):
  match fuel whole:
    case _ True{}:
      IO.pure(Socket & List<&2, U32>, (s, HTTP.x_drop32(PREFACE_LEN(), acc)))
    case 0n _:
      IO.pure(Socket & List<&2, U32>, (s, acc))
    case 1n+f _:
      do IO<Socket & List<&2, U32>>:
        r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s, 16384)
        peer_pre(f, peer_app(r, acc))

# --- scenario A: the library server sends, the raw peer is the client --

def srv(req: HTTP.Request) -> IO(HTTP.Response):
  IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, body()})

def server_side(l: Listener) -> IO(Unit):
  do IO<Unit>:
    x : Unit <- HTTP2.server.concurrent(~srv, l, CERT(), KEY())
    IO.pure(Unit, Unit{})

# The request block: a head needs :method and :path (RFC 9113 8.3.1).
def req_block() -> List<&2, U32>:
  HTTP2.x_block([HTTP.Hdr{":method", "GET"}, HTTP.Hdr{":path", "/big"}])

# Writes the preface, which is not a frame.
def send_pref(s: Socket) -> IO(Socket):
  do IO<Socket>:
    w : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(s, HTTP2.x_preface())
    IO.pure(Socket, sock_of(w))

def raw_client_conn(conn: Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        s1 : Socket <- send_pref(sock)
        s2 : Socket <- send1(s1, HTTP2.x_t_settings(), 0, 0, set_pay(WIN0()))
        s3 : Socket <- send1(s2, HTTP2.x_t_headers(), (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32), 1, req_block())
        peer(0, FUEL(), False{}, (s3, HTTP.GotErr{0, "next"}), Nil{}, 0, 0, 0, STAGE_PRE(), 0, 0, 0, Nil{}, 0, 4)

def raw_client_go(port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_insecure(HOST(), port)
    raw_client_conn(conn)

# --- scenario B: the library client uploads, the raw peer is the server -

def post() -> HTTP.Request:
  HTTP.Request{"POST", "/up", Nil{}, body()}

def cli_close(got: Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt) -> IO(Unit):
  (s, r, st) = got
  do IO<Unit>:
    x : Unit <- TLS.tls_close(s)
    IO.pure(Unit, Unit{})

def cli_conn(conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>, +port: U32) -> IO(Unit):
  match conn:
    case Fail{e}:
      IO.pure(Unit, Unit{})
    case Done{value}:
      (sock, st) = value
      do IO<Unit>:
        got : Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt <- HTTP2.client.request(sock, st, HOST(), port, post())
        cli_close(got)

def cli_go(+port: U32) -> IO(Unit):
  do IO<Unit>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTP2.client.connect_insecure(HOST(), port)
    cli_conn(conn, port)

def raw_server_pre(pre: Socket & List<&2, U32>) -> IO(U32):
  (s2, acc) = pre
  peer(0, FUEL(), True{}, (s2, HTTP.GotErr{0, "next"}), acc, 0, 0, 0, STAGE_PRE(), 0, 0, 0, Nil{}, 0, 4)

def raw_server_conn(m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        s1 : Socket <- send1(sock, HTTP2.x_t_settings(), 0, 0, set_pay(WIN0()))
        pre : Socket & List<&2, U32> <- peer_pre(64n, (s1, Nil{}))
        raw_server_pre(pre)

def raw_server_go(l: Listener) -> IO(U32):
  do IO<U32>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, CERT(), KEY())
    raw_server_conn(m)

# --- the two scenarios in one run -------------------------------------

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

# Each scenario forks the library side: the raw peer measures every frame,
# so the peer owns the score.
def main_go(a: Listener & U32, b: Listener & U32) -> IO(U32):
  (la, +pa) = a
  (lb, +pb) = b
  do IO<U32>:
    ca : Chan(Unit) <- IO.fork(Unit, server_side(la))
    +face : U32 <- raw_client_go(pa)
    cb : Chan(Unit) <- IO.fork(Unit, cli_go(pb))
    +upload : U32 <- raw_server_go(lb)
    +total : U32 = U32.add(face, upload)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

def main() -> IO(U32):
  do IO<U32>:
    a : Listener & U32 <- listen_any(32n, PORT())
    b : Listener & U32 <- listen_any(32n, (PORT() + 1 : U32))
    main_go(a, b)

#|6
