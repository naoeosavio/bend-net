# io (http2_req_trailers): the tail of a buffered request.
#
# Two scenarios against the real concurrent server:
#   scen 0: HEADERS (no END_STREAM), DATA (no END_STREAM), then a trailer
#           block with END_STREAM. The lane answers the request (task-070
#           phase 1). Before the fix the second HEADERS failed the request
#           head decode and the connection closed.
#   scen 1: HEADERS with content-length 1 (no END_STREAM), then DATA of 4
#           bytes with END_STREAM. The declared length and the body do not
#           agree, so the lane answers RST_STREAM 1 (PROTOCOL_ERROR) and
#           never calls the handler (RFC 9113 section 8.1.2.6).
#
# Score 2, one point per scenario, golden 2.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18652

def TRIES() -> Nat:
  32n

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

def HOST() -> String:
  "127.0.0.1"

def END_STREAM() -> U32:
  1

def END_HEADERS() -> U32:
  4

def RST() -> U32:
  3

def PROTOCOL() -> U32:
  1

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

def head_flags() -> U32:
  HTTP2.x_f_end_headers()

def trailers() -> List<&2, U32>:
  HTTP2.x_block([HTTP.Hdr{"x-trail", "1"}])

def req_fields(with_cl: Bool) -> List<&2, HTTP.Hdr>:
  match with_cl:
    case True{}:
      [HTTP.Hdr{":method", "POST"}, HTTP.Hdr{":scheme", "https"}, HTTP.Hdr{":path", "/"}, HTTP.Hdr{"content-length", "1"}]
    case False{}:
      [HTTP.Hdr{":method", "POST"}, HTTP.Hdr{":scheme", "https"}, HTTP.Hdr{":path", "/"}]

def req_block(with_cl: Bool) -> List<&2, U32>:
  HTTP2.x_block(req_fields(with_cl))

def data_frame(flags: U32) -> List<&2, U32>:
  HTTP2.x_frame_write(HTTP2.x_t_data(), flags, 1, [116, 101, 115, 116])

def headers_frame(flags: U32, block: List<&2, U32>) -> List<&2, U32>:
  HTTP2.x_frame_write(HTTP2.x_t_headers(), flags, 1, block)

def settings_frame() -> List<&2, U32>:
  HTTP2.x_frame_write(HTTP2.x_t_settings(), 0, 0, Nil{})

# scen 0: head, body byte-free open, then trailers that end the request.
def wire0() -> List<&2, U32>:
  List.append(&2, U32, HTTP2.x_preface(), List.append(&2, U32, settings_frame(), List.append(&2, U32, headers_frame(head_flags(), req_block(False{})), List.append(&2, U32, data_frame(0), headers_frame((END_HEADERS() + END_STREAM() : U32), trailers())))))

# scen 1: a content-length that the body does not match.
def wire1() -> List<&2, U32>:
  List.append(&2, U32, HTTP2.x_preface(), List.append(&2, U32, settings_frame(), List.append(&2, U32, headers_frame(head_flags(), req_block(True{})), data_frame(END_STREAM()))))

def is_answer(frame: HTTP.Frame) -> Bool:
  match frame:
    case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
      Bool.and(U32.is_eq(typ, HTTP2.x_t_headers()), U32.is_eq(sid, 1))

def is_reset(frame: HTTP.Frame) -> Bool:
  match frame:
    case HTTP.Frame{+typ, +flags, +sid, +flen, +payload}:
      Bool.and(U32.is_eq(typ, RST()), Bool.and(U32.is_eq(sid, 1), U32.is_eq(HTTP2.x_be32_rd(payload), PROTOCOL())))

def goal_hit(goal: U32, frame: HTTP.Frame) -> Bool:
  match goal:
    case 0:
      is_answer(frame)
    case _:
      is_reset(frame)

def hit_go(hit: Bool, score: U32) -> U32:
  match hit:
    case True{}:
      1
    case False{}:
      score

def goal_of(goal: U32) -> U32:
  match goal:
    case 0:
      1
    case _:
      2

def hit_phase(hit: Bool) -> U32:
  match hit:
    case True{}:
      3
    case False{}:
      0

# Reads frames until the goal frame arrives or the peer closes.
@unsafe
def scan(phase: U32, +goal: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +score: U32) -> IO(U32):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<U32>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
        scan(1, goal, got2, buf, score)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          do IO<U32>:
            x : Unit <- TLS.tls_close(s1)
            IO.pure(U32, score)
        case HTTP.GotOk{+frame, +buf2}:
          +hit : Bool = goal_hit(goal, frame)
          +score2 : U32 = hit_go(hit, score)
          scan(hit_phase(hit), goal, (s1, HTTP.GotOk{frame, buf2}), buf2, score2)
    case _:
      (s9, g9) = got
      do IO<U32>:
        x : Unit <- TLS.tls_close(s9)
        IO.pure(U32, score)

def run_goal(sock: Socket, +goal: U32) -> IO(U32):
  do IO<U32>:
    got : Socket & HTTP.Got <- HTTP2.x_read_frame(sock, Nil{})
    scan(0, goal, got, Nil{}, 0)

def send_go(sent: Socket & Result<&1, &1, U32 & String, Unit>, +goal: U32) -> IO(U32):
  (s, r) = sent
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{u}:
      run_goal(s, goal)

def wire_of(goal: U32) -> List<&2, U32>:
  match goal:
    case 0:
      wire0()
    case _:
      wire1()

def dialed(m: Result<&1, &1, U32 & String, Socket>, +goal: U32) -> IO(U32):
  match m:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        w : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(sock, wire_of(goal))
        send_go(w, goal)

def client(+port: U32) -> IO(U32):
  do IO<U32>:
    m0 : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_insecure(HOST(), port)
    +a : U32 <- dialed(m0, 0)
    m1 : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_insecure(HOST(), port)
    +b : U32 <- dialed(m1, 1)
    IO.pure(U32, (a + b : U32))

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

#|2
