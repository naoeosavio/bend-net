# io (http2_frame_over): a frame past the announced MAX_FRAME_SIZE answers
# GOAWAY FRAME_SIZE_ERROR.
#
# The lane announces MAX_FRAME_SIZE 65535 (x_max_str, task-070 phase 1).
# This test declares a HEADERS frame of 65536 bytes and expects the lane
# to refuse it with GOAWAY 6 before it reads any payload byte. h2spec 4.2.3
# sends a ~20 KiB frame and expects the same code, because it assumes the
# 16384 default; the lane announces 65535, so that frame is legal and this
# test pins the real cap instead.
#
# Score 1 when the GOAWAY carries code 6, golden 1.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18651

def TRIES() -> Nat:
  32n

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

def HOST() -> String:
  "127.0.0.1"

def OVER() -> U32:
  65536

def FRAME_SIZE() -> U32:
  6

def GOAWAY() -> U32:
  7

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def bytes.go(n: Nat, +b: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      bytes.go(p, b, b <> acc)

def bytes(n: Nat, +b: U32) -> List<&2, U32>:
  bytes.go(n, b, Nil{})

def body() -> List<&2, U32>:
  bytes(U32.to_nat(OVER()), 120)

def req_block() -> List<&2, U32>:
  HTTP2.x_block([HTTP.Hdr{":method", "GET"}, HTTP.Hdr{":path", "/"}, HTTP.Hdr{":scheme", "https"}])

# The preface, then one HEADERS frame whose declared length passes the cap.
def wire() -> List<&2, U32>:
  List.append(&2, U32, HTTP2.x_preface(), HTTP2.x_frame_write(HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 1, List.append(&2, U32, req_block(), body())))

def ok(req: HTTP.Request) -> IO(HTTP.Response):
  IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, Nil{}})

def server_side(l: Listener) -> IO(Unit):
  do IO<Unit>:
    x : Unit <- HTTP2.server.concurrent(~ok, l, CERT(), KEY())
    IO.pure(Unit, Unit{})

# A GOAWAY frame with the frame-size code at payload bytes 4 to 7.
def goaway_size(frame: HTTP.Frame) -> U32:
  match frame:
    case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
      b2u(Bool.and(U32.is_eq(typ, GOAWAY()), U32.is_eq(HTTP2.x_be32_rd(HTTP.x_drop32(4, payload)), FRAME_SIZE())))

# One point when a GOAWAY 6 arrives before the close. The phase
# ping-pong does not shrink a structural argument, so the def is @unsafe
# like every read loop of the suite.
@unsafe
def scan(phase: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +score: U32) -> IO(U32):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<U32>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
        scan(1, got2, buf, score)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          do IO<U32>:
            x : Unit <- TLS.tls_close(s1)
            IO.pure(U32, score)
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ2, +flags2, +sid2, +flen2, +payload2}:
              do IO<U32>:
                +score2 : U32 = (score + goaway_size(frame) : U32)
                scan(0, (s1, HTTP.GotOk{frame, buf2}), buf2, score2)
    case _:
      (s9, g9) = got
      do IO<U32>:
        x : Unit <- TLS.tls_close(s9)
        IO.pure(U32, score)

def scan_from(got: Socket & HTTP.Got) -> IO(U32):
  scan(0, got, Nil{}, 0)

def send(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  (s, r0) = m
  match r0:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got : Socket & HTTP.Got <- HTTP2.x_read_frame(s, Nil{})
        scan_from(got)

def dialed(m: Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  match m:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        w : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(sock, wire())
        send(w)

def client(port: U32) -> IO(U32):
  do IO<U32>:
    m : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_insecure(HOST(), port)
    dialed(m)

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

#|1
