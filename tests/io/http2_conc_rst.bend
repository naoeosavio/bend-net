# io (httpx_h2_conc_rst): the concurrent client must fail on a reset it
# cannot explain (task-062 phase 3, finding 3).
#
# The server is canned and sends one RST_STREAM after its SETTINGS. Two
# connections, one shape each, against HTTPX.client.concurrent_insecure
# with one request (the batch opens sid 1):
#   scen 0: RST_STREAM(1, CANCEL) -- the batch opened stream 1 and had
#           not finished it, so the call fails with the typed code and
#           text (502, "rst_stream CANCEL(8)") instead of waiting for an
#           answer that will never come;
#   scen 1: RST_STREAM(3, CANCEL) -- sid 3 is not in the batch, so the
#           call fails 502 "slot mismatch" and the caller learns the
#           frame was never its own.
# Before the fix both were ignored, the pending count never fell and the
# call waited forever on a live connection.
#
# Score: one point per scenario, golden 2.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18550

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# CANCEL, the reset the canned peer sends.
def CANCEL() -> U32:
  8

# The stream the batch opened, and one it never opened.
def OPENED_SID() -> U32:
  1

def STRANGE_SID() -> U32:
  3

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def req() -> HTTP.Request:
  HTTP.Request{"GET", "/rst", Nil{}, Nil{}}

def sc(resp: HTTP.Response) -> U32:
  0

def fail_eq(e: U32 & String, +code: U32, +msg: String) -> U32:
  (c, m) = e
  U32.mul(b2u(U32.is_eq(c, code)), b2u(String.eq(m, msg)))

# The call must fail on the reset of its own stream.
def score_opened(r: Result<&1, &1, U32 & String, U32>) -> U32:
  match r:
    case Fail{e}:
      fail_eq(e, 502, "rst_stream CANCEL(8)")
    case Done{counts}:
      0

# The call must fail on a reset of a sid the batch never opened.
def score_unopened(r: Result<&1, &1, U32 & String, U32>) -> U32:
  match r:
    case Fail{e}:
      fail_eq(e, 502, "slot mismatch")
    case Done{counts}:
      0

def score_by(+scen: U32, r: Result<&1, &1, U32 & String, U32>) -> U32:
  match scen:
    case 0:
      score_opened(r)
    case _:
      score_unopened(r)

def client_go(r: Result<&1, &1, U32 & String, U32>, +scen: U32) -> IO(U32):
  IO.pure(U32, score_by(scen, r))

def client(+port: U32, +scen: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32> <- HTTPX.client.concurrent_insecure(~sc, HOST(), port, [req()])
    client_go(r, scen)

# The sid of the reset the scenario asks for.
def rst_sid(+scen: U32) -> U32:
  match scen:
    case 0:
      OPENED_SID()
    case _:
      STRANGE_SID()

# The socket of a sent pair, for the chains that ignore the result.
def sent_sock(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket:
  (s, r) = m
  s

# Read until the client closes: the peer answers nothing else.
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

def srv_go(sock: Socket, +scen: U32) -> IO(Unit):
  do IO<Unit>:
    set : Socket & Result<&1, &1, U32 & String, Unit> <-
      HTTP2.x_send_frame(sock, HTTP2.x_t_settings(), 0, 0, HTTP2.x_settings_initial_pay())
    rst : Socket & Result<&1, &1, U32 & String, Unit> <-
      HTTP2.x_send_rst(sent_sock(set), rst_sid(scen), CANCEL())
    srv_idle_from(rst)

# One accept per scenario, in client call order.
def srv_conn(m: Listener & Result<&1, &1, U32 & String, Socket>, +scen: U32) -> IO(Listener):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l)
    case Done{sock}:
      do IO<Listener>:
        x : Unit <- srv_go(sock, scen)
        return l

def server(l: Listener) -> IO(String):
  do IO<String>:
    m0 : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, CERT(), KEY())
    l1 : Listener <- srv_conn(m0, 0)
    m1 : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l1, CERT(), KEY())
    l2 : Listener <- srv_conn(m1, 1)
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

def run(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server(l))
    +a : U32 <- client(port, 0)
    +c : U32 <- client(port, 1)
    +total : U32 = (a + c : U32)
    return total

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    +total : U32 <- run(b)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|2
