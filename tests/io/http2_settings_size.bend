# io (h2_settings_size): a SETTINGS payload that is not a multiple of six
# octets is a connection error of type FRAME_SIZE_ERROR (RFC 9113 section
# 6.5, task-068 phase 6).
#
# The frame walk carries the check, so every lane rejects the frame before
# a setting is read: before this fix `x_settings.iw_of` read the six-byte
# entries and returned on the short tail, and the frame was acked.
#
# Pure part: a six-byte and a twelve-byte payload pass, a seven-byte
# payload fails, and a PING of seven bytes fails its own fixed size
# (RFC 9113 section 6.7, task-070 phase 1).
# Wire part: a raw peer announces a seven-byte SETTINGS and reads the
# server GOAWAY. The code must be 6.
#
# Golden 5.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18850

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

def FRAME_SIZE() -> U32:
  6

def FUEL() -> Nat:
  16n

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def score_ok(is_ok: Bool) -> U32:
  b2u(is_ok)

# A SETTINGS payload of seven octets: one valid entry and one stray byte.
def bad_pay() -> List<&2, U32>:
  [0, 4, 0, 0, 0, 255, 0]

def srv(req: HTTP.Request) -> IO(HTTP.Response):
  IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, Nil{}})

def sock_of(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

def send1(s: Socket, +typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) -> IO(Socket):
  do IO<Socket>:
    w : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, typ, flags, sid, pay)
    IO.pure(Socket, sock_of(w))

def send_pref(s: Socket) -> IO(Socket):
  do IO<Socket>:
    w : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(s, HTTP2.x_preface())
    IO.pure(Socket, sock_of(w))

# The peer reads until GOAWAY. The code is the second word of the payload.
@unsafe
def peer_loop(fuel: Nat, got: Socket & HTTP.Got, +buf: List<&2, U32>, +acc: U32) -> IO(U32):
  match fuel:
    case 0n:
      (s0, g0) = got
      do IO<U32>:
        x : Unit <- TLS.tls_close(s0)
        IO.pure(U32, acc)
    case 1n+f:
      (s1, g1) = got
      do IO<U32>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s1, buf)
        peer_frame(f, got2, buf, acc)

def peer_frame(fuel: Nat, got: Socket & HTTP.Got, +buf: List<&2, U32>, +acc: U32) -> IO(U32):
  (s, g) = got
  match g:
    case HTTP.GotErr{code, msg}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s)
        IO.pure(U32, acc)
    case HTTP.GotOk{+frame, +buf2}:
      match frame:
        case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
          match typ:
            case 7:
              +code : U32 = HTTP2.x_be32_rd(HTTP.x_drop32(4, payload))
              do IO<U32>:
                x : Unit <- TLS.tls_close(s)
                IO.pure(U32, U32.add(acc, score_ok(U32.is_eq(code, FRAME_SIZE()))))
            case _:
              peer_loop(fuel, (s, HTTP.GotErr{0, "next"}), buf2, acc)

@unsafe
def peer_go(sock: Socket) -> IO(U32):
  do IO<U32>:
    s1 : Socket <- send_pref(sock)
    s2 : Socket <- send1(s1, HTTP2.x_t_settings(), 0, 0, bad_pay())
    peer_loop(FUEL(), (s2, HTTP.GotErr{0, "next"}), Nil{}, 0)

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
    +wire : U32 <- peer(port)
    +pure : U32 = U32.add(score_ok(HTTP2.x_frame.size_ok(4, 6)), U32.add(score_ok(Bool.not(HTTP2.x_frame.size_ok(4, 7))), U32.add(score_ok(HTTP2.x_frame.size_ok(4, 12)), score_ok(Bool.not(HTTP2.x_frame.size_ok(6, 7))))))
    +score : U32 = U32.add(wire, pure)
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
