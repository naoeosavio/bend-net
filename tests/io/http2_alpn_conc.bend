# lib (lib_httpx_h2_alpn_conc): the concurrent ALPN server answers H2.
# HTTPX.server.concurrent_alpn accepts the h2/http1.1 offer and serves H2.
# No test ran this entry before, so the stale H2 spawn name inside it
# (HTTP2.httpx_spawn, task 062 phase 0) went unnoticed. The client is
# client.once_insecure, which offers h2 and takes the H2 lane. Golden 1.
import Base
import ../../lib/httpx.bend as HTTPX
import ../../lib/http.bend as HTTP

def httpx_echo(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, body})

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def client_score_body(+status: U32, +body: List<&2, U32>) -> U32:
  b2u(Bool.and(U32.is_eq(status, 200), U32.is_eq(HTTP.x_eq(body, HTTP.x_str_bytes("hello")), 1)))

def client_score_resp(resp: HTTP.Response) -> U32:
  match resp:
    case HTTP.Response{+status, +headers, +body}:
      client_score_body(status, body)

def client_score(r: Result<&1, &1, U32 & String, HTTP.Response>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      client_score_resp(resp)

def client_h2(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTPX.client.once_insecure("127.0.0.1", port, HTTP.Request{"POST", "/echo", Nil{}, HTTP.x_str_bytes("hello")})
    IO.pure(U32, client_score(r))

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTPX.server.concurrent_alpn(~httpx_echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
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
    w : Unit <- IO.print(U32.show(a))
    z : Unit <- IO.die(Unit, 0, "")
    return a

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 18540)
    main_go(b)

#|1
