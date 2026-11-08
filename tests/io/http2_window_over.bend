# io (http2_window_over): a connection window that passes the cap answers
# GOAWAY FLOW_CONTROL_ERROR (task-069 phase 3).
#
# RFC 9113 section 6.9.1 terminates the connection when a WINDOW_UPDATE
# makes the connection window pass 2^31-1 octets. The client loop tracks
# that window, so an idle loop that reads the grant answers GOAWAY with
# code 3 and fails the exchange with 502.
#
# The peer sends SETTINGS and then one grant of the maximum on stream 0
# while the client window still holds the initial 65535. The sum passes
# the cap, so the client must answer the error. The peer counts the body
# bytes of the request to prove that the request went out first.
#
# Golden 5.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18952

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# The window the client starts with and the body size of the request.
def WIN0() -> U32:
  65535

def SIZE() -> U32:
  100

# The client preface is 24 bytes of magic and is not a frame.
def PREFACE_LEN() -> U32:
  24

# Frames the peer reads before it stops.
def FUEL() -> Nat:
  256n

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# The body bytes. The peer counts them and never reads a value.
def body_go(fuel: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match fuel:
    case 0n:
      acc
    case 1n+f:
      body_go(f, 97 <> acc)

def body() -> List<&2, U32>:
  body_go(U32.to_nat(SIZE()), Nil{})

# --- the pure part -----------------------------------------------------

# The initial window plus the maximum grant passes the cap, and a zero
# window plus the same grant stays at the cap.
def pure_score() -> U32:
  +over : U32 = b2u(Bool.not(HTTP2.x_win_fits(WIN0(), HTTP2.x_max_window())))
  +edge : U32 = b2u(HTTP2.x_win_fits(0, HTTP2.x_max_window()))
  U32.add(over, edge)

# --- the live part: the library client requests, the raw peer serves ----

def post() -> HTTP.Request:
  HTTP.Request{"POST", "/over", Nil{}, body()}

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

def peer_ack(s: Socket) -> IO(Socket):
  send1(s, HTTP2.x_t_settings(), HTTP2.x_f_ack(), 0, Nil{})

# The over-grant: the maximum on the connection window, on top of the
# initial 65535 the client still holds.
def peer_wu(s: Socket) -> IO(Socket):
  send1(s, HTTP2.x_t_wu(), 0, 0, HTTP.x_be32(HTTP2.x_max_window()))

# The close: three live checks, one line each, and the count.
def peer_bit(name: String, +bit: U32) -> IO(Unit):
  IO.print(String.append(name, String.append(" ", U32.show(bit))))

def peer_finish(s: Socket, +total: U32, +seen: U32, +payload: List<&2, U32>) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    +data_bit : U32 = b2u(U32.is_eq(total, SIZE()))
    +go_bit : U32 = b2u(U32.is_eq(seen, 1))
    +code_bit : U32 = b2u(U32.is_eq(HTTP2.x_goaway.code(payload), HTTP2.x_h2_err.flow()))
    p0 : Unit <- peer_bit("over.data", data_bit)
    p1 : Unit <- peer_bit("over.goaway", go_bit)
    p2 : Unit <- peer_bit("over.code", code_bit)
    +live : U32 = U32.add(data_bit, U32.add(go_bit, code_bit))
    +pure : U32 = pure_score()
    +score : U32 = U32.add(live, pure)
    w : Unit <- IO.print(U32.show(score))
    IO.pure(U32, score)

# The action of one frame: 1 acknowledges a fresh SETTINGS, 2 counts a
# DATA frame, 3 closes on our GOAWAY answer, and 0 ignores the frame.
def peer_act_set(fresh: Bool) -> U32:
  match fresh:
    case True{}:
      1
    case False{}:
      0

def peer_act(+typ: U32, +flags: U32) -> U32:
  match typ:
    case 4:
      peer_act_set(U32.is_eq(U32.and(flags, HTTP2.x_f_ack()), 0))
    case 0:
      2
    case 7:
      3
    case _:
      0

def s_of(got: Socket & HTTP.Got) -> Socket:
  (s, g) = got
  s

# The raw peer: phase 0 reads one frame, phase 1 keeps it and phase 2 acts
# on it. @unsafe: the phase ping-pong does not shrink a structural argument;
# FUEL bounds the loop.
@unsafe
def peer(ph: U32, fuel: Nat, got: Socket & HTTP.Got, +buf: List<&2, U32>, +total: U32, +seen: U32, +payload: List<&2, U32>, +typ: U32, +flags: U32, act: U32) -> IO(U32):
  match ph:
    case 0:
      match fuel:
        case 0n:
          (s0, g0) = got
          peer_finish(s0, total, seen, payload)
        case 1n+f:
          (s0, g0) = got
          do IO<U32>:
            got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
            peer(1, f, got2, buf, total, seen, payload, 0, 0, 0)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          peer_finish(s1, total, seen, payload)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ2, +flags2, +sid2, +flen2, +payload2}:
              peer(2, fuel, (s1, HTTP.GotOk{frame, buf2}), buf2, total, seen, payload2, typ2, flags2, peer_act(typ2, flags2))
    case 2:
      match act:
        case 1:
          do IO<U32>:
            s2 : Socket <- peer_ack(s_of(got))
            peer(0, fuel, (s2, HTTP.GotErr{0, "next"}), buf, total, seen, payload, 0, 0, 0)
        case 2:
          peer(0, fuel, (s_of(got), HTTP.GotErr{0, "next"}), buf, (total + HTTP.x_len32(payload) : U32), seen, payload, 0, 0, 0)
        case 3:
          peer_finish(s_of(got), total, 1, payload)
        case _:
          peer(0, fuel, (s_of(got), HTTP.GotErr{0, "next"}), buf, total, seen, payload, 0, 0, 0)
    case _:
      (s9, g9) = got
      peer_finish(s9, total, seen, payload)

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

# The over-grant goes out after the client preface, so the client reads
# it in its loop with the initial window still held.
def raw_post(pre: Socket & List<&2, U32>) -> IO(U32):
  (s2, acc) = pre
  do IO<U32>:
    s3 : Socket <- peer_wu(s2)
    peer(0, FUEL(), (s3, HTTP.GotErr{0, "next"}), acc, 0, 0, Nil{}, 0, 0, 0)

def raw_conn(m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        s1 : Socket <- send1(sock, HTTP2.x_t_settings(), 0, 0, Nil{})
        pre : Socket & List<&2, U32> <- peer_pre(64n, (s1, Nil{}))
        raw_post(pre)

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
