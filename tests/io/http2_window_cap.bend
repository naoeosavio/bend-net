# io (http2_window_cap): a peer that grants past the window cap does not
# stop the send (task-068 phase 9).
#
# The window rides signed in a U32, so a grant that crosses 2^31 turned the
# sign and the send waited for a debt the peer never owed. The lane now
# caps every grant at x_max_window(), the maximum of RFC 9113 section
# 6.9.1, so the send keeps the credit it holds.
#
# Three pure checks pin the sum: a grant past the cap answers the cap, a
# grant under it adds, and a real debt keeps its wrap. The wire check
# spends the first window of a BODY-byte upload, grants the maximum four
# times and sends a PING. A capped send finishes the body and answers the
# PING; a send that took the wrap stalls after the first window and never
# ends the stream.
#
# Golden 5.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18951

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# The window both peers start with and the body the client uploads.
def WIN0() -> U32:
  65535

def BODY() -> U32:
  200000

# The client preface is 24 bytes of magic and is not a frame.
def PREFACE_LEN() -> U32:
  24

# Frames the peer reads before it stops.
def FUEL() -> Nat:
  512n

# The stage of the peer: 0 before the over-grant, 1 after it.
def STAGE_PRE() -> U32:
  0

def STAGE_POST() -> U32:
  1

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# True from the frame that spends the first window on.
def is_spent(+total: U32) -> Bool:
  U32.is_ge(total, WIN0())

# Bytes of the body. The peer counts them and never reads a value.
def body_go(fuel: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match fuel:
    case 0n:
      acc
    case 1n+f:
      body_go(f, 97 <> acc)

def body() -> List<&2, U32>:
  body_go(U32.to_nat(BODY()), Nil{})

def PING_PAY() -> List<&2, U32>:
  HTTP.x_be32(20261105)

# A SETTINGS payload with INITIAL_WINDOW_SIZE only.
def set_pay(+v: U32) -> List<&2, U32>:
  List.append(&2, U32, HTTP2.x_be16(4), HTTP.x_be32(v))

# --- the pure part -----------------------------------------------------

# A grant past the cap answers the cap, a grant under it adds, and a debt
# keeps its wrap.
def pure_score() -> U32:
  +cap : U32 = b2u(U32.is_eq(HTTP2.x_win_add(HTTP2.x_max_window(), 1), HTTP2.x_max_window()))
  +add : U32 = b2u(U32.is_eq(HTTP2.x_win_add(100, 50), 150))
  +debt : U32 = b2u(U32.is_eq(HTTP2.x_win_add(U32.sub(0, 10), 5), U32.sub(0, 5)))
  U32.add(cap, U32.add(add, debt))

# --- the live part: the library client uploads, the raw peer serves -----

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

# --- the raw peer ------------------------------------------------------

def sock_of(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

def send1(s: Socket, +typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) -> IO(Socket):
  do IO<Socket>:
    w : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, typ, flags, sid, pay)
    IO.pure(Socket, sock_of(w))

# The over-grant: the maximum window four times, twice per window, and the
# PING whose answer closes the test.
def peer_over(s: Socket) -> IO(Socket):
  do IO<Socket>:
    s1 : Socket <- send1(s, HTTP2.x_t_wu(), 0, 1, HTTP.x_be32(HTTP2.x_max_window()))
    s2 : Socket <- send1(s1, HTTP2.x_t_wu(), 0, 1, HTTP.x_be32(HTTP2.x_max_window()))
    s3 : Socket <- send1(s2, HTTP2.x_t_wu(), 0, 0, HTTP.x_be32(HTTP2.x_max_window()))
    s4 : Socket <- send1(s3, HTTP2.x_t_wu(), 0, 0, HTTP.x_be32(HTTP2.x_max_window()))
    send1(s4, HTTP2.x_t_ping(), 0, 0, PING_PAY())

def peer_ack(s: Socket) -> IO(Socket):
  send1(s, HTTP2.x_t_settings(), HTTP2.x_f_ack(), 0, Nil{})

def peer_answer(s: Socket) -> IO(Socket):
  do IO<Socket>:
    w : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_headers(), (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32), 1, HTTP2.x_block([HTTP.Hdr{":status", "200"}]))
    IO.pure(Socket, sock_of(w))

# The close: two checks, one line each, and the count.
def peer_bit(name: String, +bit: U32) -> IO(Unit):
  IO.print(String.append(name, String.append(" ", U32.show(bit))))

def peer_finish(s: Socket, +total: U32, +ends: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    +body_bit : U32 = b2u(U32.is_eq(total, BODY()))
    +end_bit : U32 = b2u(U32.is_eq(ends, 1))
    p1 : Unit <- peer_bit("cap.body", body_bit)
    p2 : Unit <- peer_bit("cap.end", end_bit)
    +live : U32 = U32.add(body_bit, end_bit)
    +pure : U32 = pure_score()
    +score : U32 = U32.add(live, pure)
    w : Unit <- IO.print(U32.show(score))
    IO.pure(U32, score)

# The action of one frame: 1 acknowledges a fresh SETTINGS, 2 counts a
# DATA frame, 3 closes on our PING answer and 0 ignores the frame.
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

# After a DATA frame that is not the end: the first window spent starts the
# over-grant.
@unsafe
def peer_stage(stage: U32, spent: Bool, fuel: Nat, s: Socket, +buf: List<&2, U32>, +total: U32, +ends: U32) -> IO(U32):
  match stage spent:
    case 0 True{}:
      do IO<U32>:
        s2 : Socket <- peer_over(s)
        peer(0, fuel, (s2, HTTP.GotErr{0, "next"}), buf, total, ends, STAGE_POST(), 0, 0, 0, Nil{}, 0, 4)
    case _ _:
      peer(0, fuel, (s, HTTP.GotErr{0, "next"}), buf, total, ends, stage, 0, 0, 0, Nil{}, 0, 4)

@unsafe
def peer_data(end: U32, fuel: Nat, s: Socket, +buf: List<&2, U32>, +total: U32, +ends: U32, +stage: U32) -> IO(U32):
  match end:
    case 1:
      do IO<U32>:
        s2 : Socket <- peer_answer(s)
        peer(0, fuel, (s2, HTTP.GotErr{0, "next"}), buf, total, (ends + 1 : U32), stage, 0, 0, 0, Nil{}, 0, 4)
    case _:
      peer_stage(stage, is_spent(total), fuel, s, buf, total, ends)

# The raw peer: phase 0 reads one frame, phase 1 keeps it and phase 2 acts
# on it. @unsafe: the phase ping-pong does not shrink a structural argument;
# FUEL bounds the loop.
@unsafe
def peer(ph: U32, fuel: Nat, got: Socket & HTTP.Got, +buf: List<&2, U32>, +total: U32, +ends: U32, +stage: U32, +typ: U32, +flags: U32, +sid: U32, +payload: List<&2, U32>, +end: U32, act: U32) -> IO(U32):
  match ph:
    case 0:
      match fuel:
        case 0n:
          (s0, g0) = got
          peer_finish(s0, total, ends)
        case 1n+f:
          (s0, g0) = got
          do IO<U32>:
            got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
            peer(1, f, got2, buf, total, ends, stage, 0, 0, 0, Nil{}, 0, 4)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          peer_finish(s1, total, ends)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ2, +flags2, +sid2, +flen2, +payload2}:
              peer(2, fuel, (s1, HTTP.GotOk{frame, buf2}), buf2, total, ends, stage, typ2, flags2, sid2, payload2, end_flag(flags2), peer_act(typ2, flags2))
    case 2:
      match act:
        case 1:
          do IO<U32>:
            s2 : Socket <- peer_ack(s_of(got))
            peer(0, fuel, (s2, HTTP.GotErr{0, "next"}), buf, total, ends, stage, 0, 0, 0, Nil{}, 0, 4)
        case 2:
          +len : U32 = HTTP.x_len32(payload)
          peer_data(end, fuel, s_of(got), buf, (total + len : U32), ends, stage)
        case 3:
          peer_finish(s_of(got), total, ends)
        case _:
          peer(0, fuel, got, buf, total, ends, stage, 0, 0, 0, Nil{}, 0, 4)
    case _:
      (s9, g9) = got
      peer_finish(s9, total, ends)

def s_of(got: Socket & HTTP.Got) -> Socket:
  (s, g) = got
  s

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

def raw_pre(pre: Socket & List<&2, U32>) -> IO(U32):
  (s2, acc) = pre
  peer(0, FUEL(), (s2, HTTP.GotErr{0, "next"}), acc, 0, 0, STAGE_PRE(), 0, 0, 0, Nil{}, 0, 4)

def raw_conn(m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        s1 : Socket <- send1(sock, HTTP2.x_t_settings(), 0, 0, set_pay(WIN0()))
        pre : Socket & List<&2, U32> <- peer_pre(64n, (s1, Nil{}))
        raw_pre(pre)

def raw_go(l: Listener) -> IO(U32):
  do IO<U32>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, CERT(), KEY())
    raw_conn(m)

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

# The client is forked: the raw peer counts every frame, so the peer owns
# the score.
def main_go(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(Unit) <- IO.fork(Unit, cli_go(port))
    +score : U32 <- raw_go(l)
    z : Unit <- IO.die(Unit, 0, "")
    return score

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    main_go(b)

#|5
