# io (http2_clist_piw): the client seeds an upload from the peer window
# (task-068 phase 7).
#
# The client seeded every upload with the RFC default window (65535) and
# ignored the peer SETTINGS. The raw peer below announces
# INITIAL_WINDOW_SIZE 1024 and measures the first DATA frame of each upload
# on one connection:
#   * the first upload sends 16384 bytes, the largest frame, because the
#     SETTINGS is not read yet (node does the same);
#   * the second upload sends 1024 bytes at most, the announced window,
#     because the loop keeps the peer value in the CliSt.
# A client that keeps the default answers 16384 on the second upload, and
# the seed check fails.
#
# The peer prints one line for each check and the count last.
# Golden 4.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18931

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# The window the peer announces and the body of each upload.
def WIN() -> U32:
  1024

def BODY() -> U32:
  20000

# The frame the first upload sends before the peer SETTINGS is read.
def BURST() -> U32:
  16384

# The stream window the peer grants on each request HEADERS, so the body
# finishes without a credit per frame.
def GRANT() -> U32:
  65535

# Frames the peer reads before it stops: the SETTINGS exchange, the two
# uploads and a reserve.
def FUEL() -> Nat:
  128n

# The value a first length holds before any DATA frame of that stream.
def NONE() -> U32:
  4294967295

# The client preface is 24 bytes of magic and is not a frame.
def PREFACE_LEN() -> U32:
  24

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def is_seed_ok(+first: U32) -> Bool:
  Bool.and(U32.is_gt(first, 0), U32.is_le(first, WIN()))

# Bytes of one upload. The peer counts the bytes only.
def body_go(fuel: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match fuel:
    case 0n:
      acc
    case 1n+f:
      body_go(f, 97 <> acc)

def body() -> List<&2, U32>:
  body_go(U32.to_nat(BODY()), Nil{})

# --- live: the library client, two uploads on one connection -----------

def post() -> HTTP.Request:
  HTTP.Request{"POST", "/up", Nil{}, body()}

def cli_close(got: Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt) -> IO(Unit):
  (s, r, st) = got
  do IO<Unit>:
    x : Unit <- TLS.tls_close(s)
    IO.pure(Unit, Unit{})

def cli_second(got: Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt, +port: U32) -> IO(Unit):
  (s, r, st) = got
  do IO<Unit>:
    got2 : Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt <- HTTP2.client.request(s, st, HOST(), port, post())
    cli_close(got2)

def cli_first(conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>, +port: U32) -> IO(Unit):
  match conn:
    case Fail{e}:
      IO.pure(Unit, Unit{})
    case Done{value}:
      (sock, st) = value
      do IO<Unit>:
        got : Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt <- HTTP2.client.request(sock, st, HOST(), port, post())
        cli_second(got, port)

def cli_go(+port: U32) -> IO(Unit):
  do IO<Unit>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTP2.client.connect_insecure(HOST(), port)
    cli_first(conn, port)

# --- live: the raw peer -----------------------------------------------

def sock_of(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

# Writes one frame and answers the socket.
def send1(s: Socket, +typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) -> IO(Socket):
  do IO<Socket>:
    w : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, typ, flags, sid, pay)
    IO.pure(Socket, sock_of(w))

# A SETTINGS payload with INITIAL_WINDOW_SIZE only.
def peer_set_pay() -> List<&2, U32>:
  List.append(&2, U32, HTTP2.x_be16(4), HTTP.x_be32(WIN()))

def peer_answer(s: Socket, +sid: U32) -> IO(Socket):
  do IO<Socket>:
    w : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_headers(), (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32), sid, HTTP2.x_block([HTTP.Hdr{":status", "200"}]))
    IO.pure(Socket, sock_of(w))

def peer_grant(s: Socket, +sid: U32) -> IO(Socket):
  send1(s, HTTP2.x_t_wu(), 0, sid, HTTP.x_be32(GRANT()))

def peer_ack(s: Socket) -> IO(Socket):
  send1(s, HTTP2.x_t_settings(), HTTP2.x_f_ack(), 0, Nil{})

# The action of one frame: 1 acknowledges a fresh SETTINGS, 2 measures a
# DATA frame, 3 grants a request stream and 0 ignores the frame.
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
    case 1:
      3
    case _:
      0

# The phase after a frame: the second stream that ends stops the peer.
def peer_next(+e: U32) -> U32:
  match e:
    case 2:
      4
    case _:
      0

# The first length of one stream, and the value it already holds.
def first_go(fresh: Bool, +len: U32, +cur: U32) -> U32:
  match fresh:
    case True{}:
      len
    case False{}:
      cur

def first_of(is_me: Bool, +len: U32, +cur: U32) -> U32:
  first_go(Bool.and(is_me, U32.is_eq(cur, NONE())), len, cur)

# The close: four checks, one line each, and the count last.
def peer_bit(name: String, +bit: U32) -> IO(Unit):
  IO.print(String.append(name, String.append(" ", U32.show(bit))))

def peer_stop(s: Socket, +f1: U32, +f3: U32, +n: U32, +e: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    +burst : U32 = b2u(U32.is_eq(f1, BURST()))
    +seed : U32 = b2u(is_seed_ok(f3))
    +whole : U32 = b2u(U32.is_eq(n, (BODY() + BODY() : U32)))
    +ended : U32 = b2u(U32.is_eq(e, 2))
    b1 : Unit <- peer_bit("burst", burst)
    b2 : Unit <- peer_bit("seed", seed)
    b3 : Unit <- peer_bit("body", whole)
    b4 : Unit <- peer_bit("end", ended)
    +total : U32 = U32.add(burst, U32.add(seed, U32.add(whole, ended)))
    w : Unit <- IO.print(U32.show(total))
    IO.pure(U32, total)

# After a DATA frame: answer an END_STREAM frame, and stop on the second.
@unsafe
def peer_data(end: U32, fuel: Nat, s: Socket, +buf: List<&2, U32>, +f1: U32, +f3: U32, +n: U32, +e: U32, +sid: U32) -> IO(U32):
  match end:
    case 1:
      do IO<U32>:
        s2 : Socket <- peer_answer(s, sid)
        peer(peer_next(e), fuel, (s2, HTTP.GotErr{0, "next"}), buf, f1, f3, n, e, 0, 0, 0, Nil{}, 0, 4)
    case _:
      peer(0, fuel, (s, HTTP.GotErr{0, "next"}), buf, f1, f3, n, e, 0, 0, 0, Nil{}, 0, 4)

# The peer: phase 0 reads one frame, phase 1 keeps it, phase 2 acts on it
# and phase 4 closes. One def holds the chain because Bend rejects mutual
# recursion. @unsafe: the phase ping-pong does not shrink a structural
# argument; FUEL bounds the loop.
@unsafe
def peer(ph: U32, fuel: Nat, got: Socket & HTTP.Got, +buf: List<&2, U32>, +f1: U32, +f3: U32, +n: U32, +e: U32, +typ: U32, +flags: U32, +sid: U32, +payload: List<&2, U32>, +end: U32, act: U32) -> IO(U32):
  match ph:
    case 0:
      match fuel:
        case 0n:
          (s0, g0) = got
          peer_stop(s0, f1, f3, n, e)
        case 1n+f:
          (s0, g0) = got
          do IO<U32>:
            got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
            peer(1, f, got2, buf, f1, f3, n, e, 0, 0, 0, Nil{}, 0, 4)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          peer_stop(s1, f1, f3, n, e)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ2, +flags2, +sid2, +flen2, +payload2}:
              peer(2, fuel, (s1, HTTP.GotOk{frame, buf2}), buf2, f1, f3, n, e, typ2, flags2, sid2, payload2, end_flag(flags2), peer_act(typ2, flags2))
    case 2:
      match act:
        case 1:
          do IO<U32>:
            s2 : Socket <- peer_ack(s_of(got))
            peer(0, fuel, (s2, HTTP.GotErr{0, "next"}), buf, f1, f3, n, e, 0, 0, 0, Nil{}, 0, 4)
        case 2:
          +len : U32 = HTTP.x_len32(payload)
          +f1b : U32 = first_of(U32.is_eq(sid, 1), len, f1)
          +f3b : U32 = first_of(U32.is_eq(sid, 3), len, f3)
          +nb : U32 = (n + len : U32)
          +eb : U32 = (e + end : U32)
          peer_data(end, fuel, s_of(got), buf, f1b, f3b, nb, eb, sid)
        case 3:
          do IO<U32>:
            s3 : Socket <- peer_grant(s_of(got), sid)
            peer(0, fuel, (s3, HTTP.GotErr{0, "next"}), buf, f1, f3, n, e, 0, 0, 0, Nil{}, 0, 4)
        case _:
          peer(0, fuel, got, buf, f1, f3, n, e, 0, 0, 0, Nil{}, 0, 4)
    case _:
      (s9, g9) = got
      peer_stop(s9, f1, f3, n, e)

def s_of(got: Socket & HTTP.Got) -> Socket:
  (s, g) = got
  s

def end_flag(+flags: U32) -> U32:
  U32.and(flags, HTTP2.x_f_end_stream())

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

# The peer opens with its SETTINGS, reads the preface and then the frames.
def peer_go(pre: Socket & List<&2, U32>) -> IO(U32):
  (sock, acc) = pre
  peer(0, FUEL(), (sock, HTTP.GotErr{0, "next"}), acc, NONE(), NONE(), 0, 0, 0, 0, 0, Nil{}, 0, 4)

def peer_conn(m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        s1 : Socket <- send1(sock, HTTP2.x_t_settings(), 0, 0, peer_set_pay())
        pre : Socket & List<&2, U32> <- peer_pre(64n, (s1, Nil{}))
        peer_go(pre)

def peer_side(l: Listener) -> IO(U32):
  do IO<U32>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, CERT(), KEY())
    peer_conn(m)

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

# The client is forked: the peer measures every frame, so the peer owns
# the score and the process exits after it.
def main_go(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, cli_go(port))
    +score : U32 <- peer_side(l)
    z : Unit <- IO.die(Unit, 0, "")
    return score

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    main_go(b)

#|4
