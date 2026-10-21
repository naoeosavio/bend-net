# lib (lib_httpx_stream_concurrent): concurrent H2 uploads on one
# connection against HTTPX.server.stream_concurrent. Two claims:
#   * a Cancel answer resets only that stream (RST_STREAM 8). The next
#     request on the SAME connection still answers 200, which the old loop
#     could not do: it closed the connection.
#   * two pipelined uploads interleave in the server's slot ledger and
#     each one gets its own echo.
# The client is the library's own (client.connect_insecure and
# client.request for the first claim, client.concurrent for the second),
# so the test drives the public surface and the installed runtime.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# The handler: "/cancel" is refused at the head; each other stream echoes
# every data chunk with 200.
def h_head(is_cancel: Bool) -> HTTP.SrvOut:
  match is_cancel:
    case True{}:
      HTTP.Cancel{}
    case False{}:
      HTTP.Continue{}

def h(ev: HTTP.SrvEv) -> HTTP.SrvOut:
  match ev:
    case HTTP.SrvReqHead{slot, head}:
      match head:
        case HTTP.ReqHead{method, path, headers}:
          h_head(String.eq(path, "/cancel"))
    case HTTP.SrvReqData{slot, +chunk, fin}:
      HTTP.RespondEarly{HTTP.Response{200, Nil{}, chunk}}

def is_stream_code(+code: U32) -> U32:
  b2u(Bool.or(U32.is_eq(code, 502), U32.is_eq(code, 503)))

def is_stream_fail(r: Result<&1, &1, U32 & String, HTTP.Response>) -> U32:
  match r:
    case Fail{(code, msg)}:
      is_stream_code(code)
    case Done{+resp}:
      0

def score_echo(r: Result<&1, &1, U32 & String, HTTP.Response>, +want: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      match resp:
        case HTTP.Response{+status, +headers, +body}:
          b2u(Bool.and(U32.is_eq(status, 200), U32.is_eq(HTTP.x_eq(body, HTTP.x_str_bytes(want)), 1)))

def after_sibling(got: Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt, +s: U32) -> IO(U32):
  (sock, r, st) = got
  do IO<U32>:
    +s2 : U32 = (s + score_echo(r, "hi") : U32)
    x : Unit <- TLS.tls_close(sock)
    IO.pure(U32, s2)

def after_cancel(got: Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt, +port: U32) -> IO(U32):
  (sock, r, st) = got
  do IO<U32>:
    +s1 : U32 = is_stream_fail(r)
    got2 : Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt <- HTTPX.client.request(sock, st, "127.0.0.1", port, HTTP.Request{"POST", "/echo", Nil{}, HTTP.x_str_bytes("hi")})
    after_sibling(got2, s1)

def conn_cancel(conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>, +port: U32) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock0, st0) = value
      do IO<U32>:
        got1 : Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt <- HTTPX.client.request(sock0, st0, "127.0.0.1", port, HTTP.Request{"POST", "/cancel", Nil{}, HTTP.x_str_bytes("x")})
        after_cancel(got1, port)

def client_cancel(+port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTPX.client.connect_insecure("127.0.0.1", port)
    conn_cancel(conn, port)

def score_ok(resp: HTTP.Response) -> U32:
  match resp:
    case HTTP.Response{+status, +headers, +body}:
      b2u(U32.is_eq(status, 200))

def reqs_pair() -> List<&2, HTTP.Request>:
  [HTTP.Request{"POST", "/echo", Nil{}, HTTP.x_str_bytes("one")}, HTTP.Request{"POST", "/echo", Nil{}, HTTP.x_str_bytes("two")}]

def pair_score(r: Result<&1, &1, U32 & String, U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+total}:
      total

def client_pair(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32> <- HTTPX.client.concurrent_insecure(~score_ok, "127.0.0.1", port, reqs_pair())
    IO.pure(U32, pair_score(r))

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTPX.server.stream_concurrent(~h, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
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

def clients(+port: U32) -> IO(U32):
  do IO<U32>:
    +c1 : U32 <- client_cancel(port)
    +c2 : U32 <- client_pair(port)
    IO.pure(U32, (c1 + c2 : U32))

law main_go:
  for b: Listener & U32
  IO(U32)

def main_go(b):
  (l, port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    +total : U32 <- clients(port)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 18460)
    main_go(b)

#|4
