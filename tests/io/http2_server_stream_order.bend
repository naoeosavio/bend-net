# io (httpx_h2_server_stream_order): the ordered admission of the H2
# server stream lane (task-059 phase 2). One connection against
# HTTP2.server.stream.on. The raw client opens stream 1 with a HEADERS
# that does not end the stream, then sends stream 3 while stream 1 is
# still open. The ordered lane must refuse stream 3 with RST_STREAM 7
# (REFUSED_STREAM) and keep the connection: stream 1 still gets its 200
# when its body arrives, and stream 5 is served on the same connection.
# Pre-fix behavior: the lane did not exist, or the second stream was
# admitted.
#
# Score: RST 7 on stream 3 +1, the 200 head of stream 1 +1, the 200 head
# of stream 5 +1, golden 3.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

def hi_bytes() -> List<&2, U32>:
  HTTP.x_str_bytes("hi")

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# Server handler: Continue on the head, echo 200 on the data.
def h(ev: HTTP.SrvEv) -> HTTP.SrvOut:
  match ev:
    case HTTP.SrvReqHead{slot, head}:
      HTTP.Continue{}
    case HTTP.SrvReqData{slot, +chunk, fin}:
      HTTP.RespondEarly{HTTP.Response{200, Nil{}, chunk}}

def blk(+method: String, +path: String) -> List<&2, U32>:
  HTTP2.client.on.req_block(HOST(), 0, method, path, Nil{})

# The whole exchange in one write: HEADERS 1 (open), HEADERS 3 (refused
# while 1 is open), DATA 1 (ends 1, "hi"), HEADERS 5 (open) and DATA 5
# (ends 5, "hi"). The third HEADERS is served on the same connection.
def wire() -> List<&2, U32>:
  List.append(&2, U32,
    HTTP2.x_frame_write(HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 1, blk("POST", "/echo")),
    List.append(&2, U32,
      HTTP2.x_frame_write(HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 3, blk("GET", "/")),
      List.append(&2, U32,
        HTTP2.x_frame_write(HTTP2.x_t_data(), HTTP2.x_f_end_stream(), 1, hi_bytes()),
        List.append(&2, U32,
          HTTP2.x_frame_write(HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 5, blk("POST", "/echo")),
          HTTP2.x_frame_write(HTTP2.x_t_data(), HTTP2.x_f_end_stream(), 5, hi_bytes())))))

# Frame class -> loop act: 2 settings ack, 3 RST, 4 head. A settings ACK
# is not acked back.
def act_of(+typ: U32, +flags: U32) -> U32:
  match typ:
    case 4:
      match flags:
        case 1:
          0
        case _:
          2
    case 3:
      3
    case 1:
      4
    case _:
      0

def acked(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & HTTP.Got:
  (s2, r) = sent
  match r:
    case Fail{e}:
      (s2, HTTP.GotErr{616, "tls io"})
    case Done{u}:
      (s2, HTTP.GotErr{0, "next"})

def status_of(head: HTTP.Head) -> U32:
  match head:
    case HTTP.Head{status, headers}:
      status

# A refusal of stream 3 carries RST_STREAM with code 7.
def rst7(+sid: U32, +payload: List<&2, U32>) -> U32:
  b2u(Bool.and(U32.is_eq(sid, 3), U32.is_eq(HTTP.x_eq(payload, HTTP.x_be32(7)), 1)))

def head_hit(+sid: U32, +st: U32) -> U32:
  b2u(Bool.and(Bool.or(U32.is_eq(sid, 1), U32.is_eq(sid, 5)), U32.is_eq(st, 200)))

# 9 closes and answers the score; 0 reads the next frame.
def goal_phase(+score: U32) -> U32:
  match score:
    case 3:
      9
    case _:
      0

@unsafe
def collect(phase: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +score: U32, +tab: HTTP.Tab) -> IO(U32):
  match phase:
    case 0:
      (s0, g0) = got
      do IO<U32>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
        collect(1, got2, buf, score, tab)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code1, msg1}:
          match code1:
            case 0:
              collect(0, got, buf, score, tab)
            case _:
              do IO<U32>:
                x : Unit <- TLS.tls_close(s1)
                IO.pure(U32, score)
        case HTTP.GotOk{+frame1, +buf1}:
          match frame1:
            case HTTP.Frame{+typ1, +flags1, +sid1, +payload1}:
              dispatch(act_of(typ1, flags1), (s1, HTTP.GotOk{frame1, buf1}), buf1, typ1, flags1, sid1, payload1, score, tab)
    case 9:
      (s9, g9) = got
      do IO<U32>:
        x : Unit <- TLS.tls_close(s9)
        IO.pure(U32, score)
    case _:
      (s8, g8) = got
      do IO<U32>:
        x : Unit <- TLS.tls_close(s8)
        IO.pure(U32, score)

def dispatch(act: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +typ: U32, +flags: U32, +sid: U32, +payload: List<&2, U32>, +score: U32, +tab: HTTP.Tab) -> IO(U32):
  match act:
    case 2:
      (s2, g2) = got
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s2, HTTP2.x_t_settings(), HTTP2.x_f_ack(), 0, Nil{})
        collect(0, acked(sent), buf, score, tab)
    case 3:
      +s3 : U32 = (score + rst7(sid, payload) : U32)
      collect(goal_phase(s3), got, buf, s3, tab)
    case 4:
      +s4 : U32 = (score + head_hit(sid, status_of(HTTP2.x_resp.rh(HTTP2.x_resp.decode(payload, tab)))) : U32)
      collect(goal_phase(s4), got, buf, s4, HTTP2.x_resp.tab(HTTP2.x_resp.decode(payload, tab)))
    case _:
      collect(0, got, buf, score, tab)

def sent_go(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  (s, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got : Socket & HTTP.Got <- HTTP2.x_read_frame(s, Nil{})
        collect(1, got, Nil{}, 0, HTTP2.x_tab.empty())

def client_fire(sock: Socket) -> IO(U32):
  do IO<U32>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(sock, wire())
    sent_go(sent)

def client_conn(conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, st) = value
      client_fire(sock)

law client:
  for +port: U32
  IO(U32)

def client(port):
  do IO<U32>:
    c : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTP2.client.connect_insecure(HOST(), port)
    client_conn(c)

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTP2.server.stream.on(~h, l, CERT(), KEY())
    return "up"

law listen_retry:
  for port: U32
  for r: Result<&1, &1, (U32 & String), Listener>
  for rest: IO(Listener & U32)
  IO(Listener & U32)

def listen_retry(port, r, rest):
  match r:
    case Done{l}:
      IO.pure(Listener & U32, (l, port))
    case Fail{e}:
      rest

law listen_any:
  for tries: Nat
  for +port: U32
  IO(Listener & U32)

def listen_any(tries, port):
  match tries:
    case 0n:
      IO.die(Listener & U32, 1, "no free tcp port")
    case 1n+t:
      rest = listen_any(t, (port + 1 : U32))
      do IO<Listener & U32>:
        r : Result<&1, &1, (U32 & String), Listener> <- TCP.listen(port)
        listen_retry(port, r, rest)

law main_go:
  for b: Listener & U32
  IO(U32)

def main_go(b):
  (l, port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    +a : U32 <- client(port)
    +total : U32 = (a : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 18730)
    main_go(b)

#|3
