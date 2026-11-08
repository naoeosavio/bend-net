# io (h2_window_big): the send starts from a large announced stream
# window, so a body past 65535 bytes does not stop (task-068 phase 6).
#
# The peer announces an INITIAL_WINDOW_SIZE of WIN bytes and grants the
# same amount on the connection before the request. The server sends the
# whole 262144-byte body without one stream WINDOW_UPDATE, in frames of
# x_max_send() bytes. A send seeded with the RFC default would stop at
# 65535 bytes and wait for credit that this peer never grants for the
# stream, because it announces a window it has already given.
#
# Checks: the whole body (1), every DATA frame at most x_max_send()
# bytes (2), and END_STREAM (4). All three answer 7.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18854

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# The announced stream window, and the body the handler answers. The body
# is half the window, so no stream credit is due before it ends.
def WIN() -> U32:
  524288

def BODY() -> U32:
  262144

def FUEL() -> Nat:
  64n

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

def sock_of(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

def is_end(+flags: U32) -> Bool:
  U32.is_eq(U32.and(flags, HTTP2.x_f_end_stream()), HTTP2.x_f_end_stream())

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

def set_pay(+v: U32) -> List<&2, U32>:
  List.append(&2, U32, HTTP2.x_be16(4), HTTP.x_be32(v))

def req_block() -> List<&2, U32>:
  HTTP2.x_block([HTTP.Hdr{":method", "GET"}, HTTP.Hdr{":path", "/big"}, HTTP.Hdr{":scheme", "https"}])

def send1(s: Socket, +typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) -> IO(Socket):
  do IO<Socket>:
    w : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, typ, flags, sid, pay)
    IO.pure(Socket, sock_of(w))

def send_pref(s: Socket) -> IO(Socket):
  do IO<Socket>:
    w : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(s, HTTP2.x_preface())
    IO.pure(Socket, sock_of(w))

# The bits the frame proves: the body is whole, every frame is inside the
# frame cap, and the stream ends.
def finish(s: Socket, +total: U32, +oversize: U32, done: Bool) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    +whole : U32 = weigh(U32.is_eq(total, BODY()), 1)
    +limit : U32 = weigh(U32.is_eq(oversize, 0), 2)
    +fin : U32 = weigh(done, 4)
    IO.pure(U32, U32.add(whole, U32.add(limit, fin)))

def frame_ok(+sid: U32, +pay: List<&2, U32>, +oversize: U32) -> U32:
  U32.add(oversize, b2u(U32.is_gt(HTTP.x_len32(pay), HTTP2.x_max_send())))

@unsafe
def peer_loop(fuel: Nat, got: Socket & HTTP.Got, +buf: List<&2, U32>, +total: U32, +oversize: U32) -> IO(U32):
  match fuel:
    case 0n:
      (s0, g0) = got
      finish(s0, total, oversize, False{})
    case 1n+f:
      (s1, g1) = got
      do IO<U32>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s1, buf)
        peer_frame(f, got2, buf, total, oversize)

@unsafe
def peer_frame(fuel: Nat, got: Socket & HTTP.Got, +buf: List<&2, U32>, +total: U32, +oversize: U32) -> IO(U32):
  (s, g) = got
  match g:
    case HTTP.GotErr{code, msg}:
      finish(s, total, oversize, False{})
    case HTTP.GotOk{+frame, +buf2}:
      match frame:
        case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
          match typ:
            case 4:
              do IO<U32>:
                s2 : Socket <- ack_settings(s, flags)
                peer_loop(fuel, (s2, HTTP.GotErr{0, "next"}), buf2, total, oversize)
            case 0:
              do IO<U32>:
                +t2 : U32 = (total + HTTP.x_len32(payload) : U32)
                +o2 : U32 = frame_ok(sid, payload, oversize)
                end_go(is_end(flags), s, buf2, fuel, t2, o2)
            case _:
              peer_loop(fuel, (s, HTTP.GotErr{0, "next"}), buf2, total, oversize)

def end_go(fin: Bool, s: Socket, +buf: List<&2, U32>, fuel: Nat, +total: U32, +oversize: U32) -> IO(U32):
  match fin:
    case True{}:
      finish(s, total, oversize, True{})
    case False{}:
      peer_loop(fuel, (s, HTTP.GotErr{0, "next"}), buf, total, oversize)

def ack_go(s: Socket, is_fresh: Bool) -> IO(Socket):
  match is_fresh:
    case True{}:
      send1(s, HTTP2.x_t_settings(), HTTP2.x_f_ack(), 0, Nil{})
    case False{}:
      IO.pure(Socket, s)

def ack_settings(s: Socket, +flags: U32) -> IO(Socket):
  ack_go(s, U32.is_eq(U32.and(flags, HTTP2.x_f_ack()), 0))

def peer_go(sock: Socket) -> IO(U32):
  do IO<U32>:
    s1 : Socket <- send_pref(sock)
    s2 : Socket <- send1(s1, HTTP2.x_t_settings(), 0, 0, set_pay(WIN()))
    s3 : Socket <- send1(s2, HTTP2.x_t_wu(), 0, 0, HTTP.x_be32(WIN()))
    s4 : Socket <- send1(s3, HTTP2.x_t_headers(), (HTTP2.x_f_end_headers() + HTTP2.x_f_end_stream() : U32), 1, req_block())
    peer_loop(FUEL(), (s4, HTTP.GotErr{0, "next"}), Nil{}, 0, 0)

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

#|7
