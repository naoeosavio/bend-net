# lib (lib_httpx_server_alpn): ALPN split of the sequential server (Phase 11).
# Server is HTTPX.server.on_alpn with one handler for both lanes; client one
# is HTTPX.client.once_insecure (negotiates h2, H2 lane) and client two is
# HTTPX.h1_once_insecure (no-ALPN dial, negotiates http/1.1, H1 lane). Both
# POST "hello" and expect the 200 echo. Golden 2.
import Base
import ../../lib/httpx.bend as HTTPX

def httpx_echo(req: HTTPX.Request) -> IO(HTTPX.Response):
  match req:
    case HTTPX.Request{+method, +path, +headers, +body}:
      IO.pure(HTTPX.Response, HTTPX.Response{200, Nil{}, body})

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def client_score_body(+status: U32, +body: List<&2, U32>) -> U32:
  b2u(Bool.and(U32.is_eq(status, 200), U32.is_eq(HTTPX.x_eq(body, HTTPX.x_str_bytes("hello")), 1)))

def client_score_resp(resp: HTTPX.Response) -> U32:
  match resp:
    case HTTPX.Response{+status, +headers, +body}:
      client_score_body(status, body)

def client_score(r: Result<&1, &1, U32 & String, HTTPX.Response>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      client_score_resp(resp)

def client_h2(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTPX.Response> <- HTTPX.client.once_insecure("127.0.0.1", port, HTTPX.Request{"POST", "/echo", Nil{}, HTTPX.x_str_bytes("hello")})
    IO.pure(U32, client_score(r))

def client_h1(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTPX.Response> <- HTTPX.h1_once_insecure("127.0.0.1", port, "POST", "/echo", Nil{}, HTTPX.x_str_bytes("hello"))
    IO.pure(U32, client_score(r))

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTPX.server.on_alpn(~httpx_echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
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
  (l, +port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    +a : U32 <- client_h2(port)
    +c : U32 <- client_h1(port)
    +total : U32 = (a + c : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 18440)
    main_go(b)

#|2
