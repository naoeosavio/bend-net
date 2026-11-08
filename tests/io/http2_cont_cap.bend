# io (httpx_h2_cont_cap): a header block that never ends must not grow
# the fragment list without a limit (task-062 phase 1).
#
# Scenario A is the server. The peer is a raw H2 client: it connects
# through HTTPX.client.connect_insecure (preface, SETTINGS, ALPN) and then
# sends HEADERS without END_HEADERS plus four 16384-byte CONTINUATIONs
# against HTTPX.server.concurrent. The block passes the 65536-byte cap on
# the fourth fragment, so the server answers GOAWAY(ENHANCE_YOUR_CALM 11)
# and closes the connection. Before the fix the server appended every
# fragment and waited for an END_HEADERS that a hostile peer never sends.
#
# Scenario B is the client. The peer is a canned H2 server: it sends
# SETTINGS, one HEADERS(:status 200, no END_HEADERS) and four 16384-byte
# CONTINUATIONs to HTTPX.client.once_insecure. The client answers
# Fail{431, "header block too large"} and closes. Before the fix the
# client appended the fragments until the peer stopped sending.
#
# Score: one point for the GOAWAY, one for the 431, golden 2.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

# Two ports: one listener for each scenario.
def PORT_A() -> U32:
  18545

def PORT_B() -> U32:
  18546

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# Bytes per CONTINUATION frame: the minimum legal MAX_FRAME_SIZE.
def SLICE() -> U32:
  16384

# Fragments after the HEADERS: four of them pass 65536 bytes.
def FRAGS() -> Nat:
  4n

# Frames the peer reads before it gives up.
def FUEL() -> Nat:
  32n

# RFC 9113 section 7.1 ENHANCE_YOUR_CALM, the GOAWAY code of the server.
def CALM() -> U32:
  11

# The fail code and text of the client.
def FAIL() -> U32:
  431

def MSG() -> String:
  "header block too large"

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# A list of n zero bytes, built tail-recursively.
def filler_go(+n: Nat, +acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      filler_go(p, 0 <> acc)

def filler(+n: Nat) -> List<&2, U32>:
  filler_go(n, Nil{})

# Sends fuel CONTINUATION frames of the same payload on one stream.
def cont_send(fuel: Nat, m: Socket & Result<&1, &1, U32 & String, Unit>, +sid: U32, +pay: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match fuel:
    case 0n:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, m)
    case 1n+p:
      (s, r) = m
      match r:
        case Fail{e}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s, Fail{e}))
        case Done{u}:
          do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <-
              HTTP2.x_send_frame(s, HTTP2.x_t_cont(), 0, sid, pay)
            cont_send(p, sent, sid, pay)

# A send becomes the seed of the read loop: a failed write keeps the code.
def sent_seed(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & HTTP.Got:
  (s, r) = m
  match r:
    case Fail{(code, msg)}:
      (s, HTTP.GotErr{code, msg})
    case Done{u}:
      (s, HTTP.GotErr{0, "next"})

# Scenario A: the peer reads until the GOAWAY, EOF or the fuel runs out.
def stop_goaway(pay: List<&2, U32>) -> U32:
  b2u(U32.is_eq(HTTP2.x_goaway.code(pay), CALM()))

def stop_at(got: Socket & HTTP.Got, +score: U32) -> Socket & U32:
  (s, g) = got
  (s, score)

# 0 a plain read, 1 route, 2 GOAWAY, 3 SETTINGS to ack.
def route(+typ: U32, +flags: U32) -> U32:
  match typ flags:
    case 7 _:
      2
    case 4 1:
      0
    case 4 _:
      3
    case _ _:
      0

def peer_read(fuel: Nat, ph: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>) ->
  IO(Socket & U32):
  match fuel:
    case 0n:
      IO.pure(Socket & U32, stop_at(got, 0))
    case 1n+p:
      match ph:
        case 0:
          (s0, g0) = got
          do IO<Socket & U32>:
            got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
            peer_read(p, 1, got2, buf)
        case 1:
          (s1, g1) = got
          match g1:
            case HTTP.GotErr{code, msg}:
              IO.pure(Socket & U32, stop_at(got, 0))
            case HTTP.GotOk{+frame, +buf2}:
              match frame:
                case HTTP.Frame{+typ, +flags, +sid,+flen, +payload}:
                  peer_read(p, route(typ, flags), (s1, HTTP.GotOk{frame, buf2}), buf2)
        case 2:
          (s2, g2) = got
          match g2:
            case HTTP.GotErr{code, msg}:
              IO.pure(Socket & U32, stop_at(got, 0))
            case HTTP.GotOk{+frame, +buf2}:
              match frame:
                case HTTP.Frame{+typ, +flags, +sid,+flen, +payload}:
                  IO.pure(Socket & U32, stop_at((s2, HTTP.GotOk{frame, buf2}), stop_goaway(payload)))
        case 3:
          (s3, g3) = got
          do IO<Socket & U32>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <-
              HTTP2.x_send_frame(s3, HTTP2.x_t_settings(), HTTP2.x_f_ack(), 0, Nil{})
            peer_read(p, 0, sent_seed(sent), buf)
        case _:
          (s9, g9) = got
          peer_read(p, 0, (s9, HTTP.GotErr{0, "next"}), buf)

def peer_done(m: Socket & U32) -> IO(U32):
  (s, +score) = m
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    return score

def peer_go(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  (s, r) = m
  match r:
    case Fail{e}:
      peer_done((s, 0))
    case Done{u}:
      do IO<U32>:
        got : Socket & HTTP.Got <- HTTP2.x_read_frame(s, Nil{})
        res : Socket & U32 <- peer_read(FUEL(), 1, got, Nil{})
        peer_done(res)

def peer_start(sock: Socket) -> IO(U32):
  do IO<U32>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <-
      HTTP2.x_send_frame(sock, HTTP2.x_t_headers(), 0, 1, HTTP2.client.on.req_block(HOST(), PORT_A(), "GET", "/cap", Nil{}))
    rest : Socket & Result<&1, &1, U32 & String, Unit> <-
      cont_send(FRAGS(), sent, 1, filler(U32.to_nat(SLICE())))
    peer_go(rest)

def peer_conn(conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, st) = value
      peer_start(sock)

def peer(+port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTPX.client.connect_insecure(HOST(), port)
    peer_conn(conn)

# Scenario B: a canned server floods the real client.
def head_block() -> List<&2, U32>:
  HTTP2.x_block([HTTP.Hdr{":status", "200"}])

@unsafe
def srv_idle(got: Socket & HTTP.Got) -> IO(Unit):
  (s, g) = got
  match g:
    case HTTP.GotErr{code, msg}:
      TLS.tls_close(s)
    case HTTP.GotOk{+frame, +buf2}:
      do IO<Unit>:
        got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s, buf2)
        srv_idle(got2)

def srv_idle_from(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      srv_idle((s, HTTP.GotErr{0, "next"}))

# The socket of a sent pair, for the chains that ignore the result.
def sent_sock(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

def srv_head(sock: Socket) -> IO(Unit):
  do IO<Unit>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <-
      HTTP2.x_send_frame(sock, HTTP2.x_t_headers(), 0, 1, head_block())
    rest : Socket & Result<&1, &1, U32 & String, Unit> <-
      cont_send(FRAGS(), sent, 1, filler(U32.to_nat(SLICE())))
    srv_idle_from(rest)

def srv_settings(sock: Socket) -> IO(Unit):
  do IO<Unit>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <-
      HTTP2.x_send_frame(sock, HTTP2.x_t_settings(), 0, 0, HTTP2.x_settings_initial_pay())
    srv_head(sent_sock(sent))

def srv_conn(m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      do IO<Listener>:
        x : Unit <- srv_settings(sock)
        return l

def server_b(l: Listener) -> IO(String):
  do IO<String>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, CERT(), KEY())
    l2 : Listener <- srv_conn(m)
    return "up"

# The real client against the canned server.
def want_fail(r: Result<&1, &1, U32 & String, HTTP.Response>) -> U32:
  match r:
    case Fail{(code, msg)}:
      U32.mul(b2u(U32.is_eq(code, FAIL())), b2u(String.eq(msg, MSG())))
    case Done{resp}:
      0

def client_once(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <-
      HTTPX.client.once_insecure(HOST(), port, HTTP.Request{"GET", "/cap", Nil{}, Nil{}})
    IO.pure(U32, want_fail(r))

# Scenario A server: the real buffered concurrent lane, echo handler.
def echo(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, body})

def server_a(l: Listener) -> IO(String):
  do IO<String>:
    x : Unit <- HTTPX.server.concurrent(~echo, l, CERT(), KEY())
    return "up"

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

def run_a(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_a(l))
    +score : U32 <- peer(port)
    return score

def run_b(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_b(l))
    +score : U32 <- client_once(port)
    return score

def main() -> IO(U32):
  do IO<U32>:
    ba : Listener & U32 <- listen_any(32n, PORT_A())
    bb : Listener & U32 <- listen_any(32n, PORT_B())
    +a : U32 <- run_a(ba)
    +c : U32 <- run_b(bb)
    +total : U32 = (a + c : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|2
