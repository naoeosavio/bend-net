# fuzz (h2_fuzz_wire): malformed frames over TLS, against the real server.
#
# Six scenarios, one connection each. The peer sends the client preface
# and one frame that the server must refuse, then reads until the server
# answers GOAWAY or closes the connection. A scenario scores when the
# connection ends that way before the frame budget is spent.
#
#   0 DATA on stream 0                  GOAWAY 1
#   1 PING of four octets               GOAWAY 6
#   2 RST_STREAM on stream 0            GOAWAY 1
#   3 WINDOW_UPDATE of increment 0      GOAWAY 1
#   4 PRIORITY that depends on itself   GOAWAY 1
#   5 a truncated frame, then close     server closes
#
# Golden 6.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18653

def TRIES() -> Nat:
  32n

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

def HOST() -> String:
  "127.0.0.1"

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def ok(req: HTTP.Request) -> IO(HTTP.Response):
  IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, Nil{}})

def server_side(l: Listener) -> IO(Unit):
  do IO<Unit>:
    x : Unit <- HTTP2.server.concurrent(~ok, l, CERT(), KEY())
    IO.pure(Unit, Unit{})

# A preface and one bad frame, per scenario.
def wire_go(+s: List<&2, U32>, k: U32) -> List<&2, U32>:
  match k:
    case 0:
      List.append(&2, U32, s, HTTP2.x_frame_write(HTTP2.x_t_data(), 0, 0, [1, 2]))
    case 1:
      List.append(&2, U32, s, HTTP2.x_frame_write(HTTP2.x_t_ping(), 0, 0, [0, 0, 0, 0]))
    case 2:
      List.append(&2, U32, s, HTTP2.x_frame_write(HTTP2.x_t_rst(), 0, 0, [0, 0, 0, 0]))
    case 3:
      List.append(&2, U32, s, HTTP2.x_frame_write(HTTP2.x_t_wu(), 0, 0, [0, 0, 0, 0]))
    case 4:
      List.append(&2, U32, s, HTTP2.x_frame_write(2, 0, 1, [0, 0, 0, 1, 16]))
    case _:
      List.append(&2, U32, s, [0, 0, 5, 1, 4])

def frame_typ(frame: HTTP.Frame) -> U32:
  match frame:
    case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
      typ

def is_refusal(frame: HTTP.Frame, +k: U32) -> Bool:
  match k:
    case 5:
      False{}
    case _:
      U32.is_eq(frame_typ(frame), HTTP2.x_t_goaway())

# 1 when the server refused the frame; phase 2 closes and returns the score.
@unsafe
def scan(phase: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +score: U32, +k: U32, fuel: Nat) -> IO(U32):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<U32>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
        scan(1, got2, buf, score, k, fuel)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          do IO<U32>:
            x : Unit <- TLS.tls_close(s1)
            IO.pure(U32, 1)
        case HTTP.GotOk{+frame, +buf2}:
          scan(stop_of(is_refusal(frame, k)), (s1, HTTP.GotOk{frame, buf2}), buf2, (score + b2u(is_refusal(frame, k)) : U32), k, fuel)
    case _:
      (s9, g9) = got
      do IO<U32>:
        x : Unit <- TLS.tls_close(s9)
        IO.pure(U32, score)

def stop_of(hit: Bool) -> U32:
  match hit:
    case True{}:
      3
    case False{}:
      0

def wire(k: U32) -> List<&2, U32>:
  wire_go(HTTP2.x_preface(), k)

# A peer that closes after a truncated frame ends the connection.
def close_of(k: U32) -> U32:
  match k:
    case 5:
      1
    case _:
      0

def close_go(sock: Socket, +k: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(sock)
    IO.pure(U32, close_of(k))

def send5(sent: Socket & Result<&1, &1, U32 & String, Unit>, +k: U32) -> IO(U32):
  (s, r) = sent
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{u}:
      close_go(s, k)

def send_go(sent: Socket & Result<&1, &1, U32 & String, Unit>, +k: U32) -> IO(U32):
  (s, r) = sent
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got : Socket & HTTP.Got <- HTTP2.x_read_frame(s, Nil{})
        scan(0, got, Nil{}, 0, k, 8n)

def sent_go(+k: U32, sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  match k:
    case 5:
      send5(sent, k)
    case _:
      send_go(sent, k)

def done_go(+k: U32, sock: Socket) -> IO(U32):
  do IO<U32>:
    w : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(sock, wire(k))
    sent_go(k, w)

def dialed(m: Result<&1, &1, U32 & String, Socket>, +k: U32) -> IO(U32):
  match m:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      done_go(k, sock)

def client(+port: U32) -> IO(U32):
  do IO<U32>:
    m0 : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_insecure(HOST(), port)
    +a : U32 <- dialed(m0, 0)
    m1 : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_insecure(HOST(), port)
    +b : U32 <- dialed(m1, 1)
    m2 : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_insecure(HOST(), port)
    +c : U32 <- dialed(m2, 2)
    m3 : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_insecure(HOST(), port)
    +d : U32 <- dialed(m3, 3)
    m4 : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_insecure(HOST(), port)
    +e : U32 <- dialed(m4, 4)
    m5 : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_insecure(HOST(), port)
    +f : U32 <- dialed(m5, 5)
    IO.pure(U32, (a + b + c + d + e + f : U32))

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

def main_go(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(Unit) <- IO.fork(Unit, server_side(l))
    +total : U32 <- client(port)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(TRIES(), PORT())
    main_go(b)

#|6
