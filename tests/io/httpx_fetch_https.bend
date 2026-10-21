# lib (lib_httpx_fetch_https): loopback against the httpx server. The server
# accepts one TLS connection and serves the echo handler once via
# HTTPX.server.once; the client POSTs "hello" with
# HTTPX.request_insecure and checks the echo. Golden 1.
import Base
import ../../lib/httpx.bend as HTTPX
import ../../lib/http.bend as HTTP

def h2_echo(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, body})

def is_hello.go(same: Bool) -> U32:
  match same:
    case True{}:
      1
    case False{}:
      0

def is_hello(s: String) -> U32:
  is_hello.go(String.eq(s, "hello"))

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTPX.server.once(~h2_echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    return "up"

def client_score(r: Result<&1, &1, (U32 & String), String>) -> IO(U32):
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{+body}:
      IO.pure(U32, is_hello(body))

law client:
  for port: U32
  IO(U32)

def client(port):
  do IO<U32>:
    r : Result<&1, &1, (U32 & String), String> <- HTTPX.request_insecure("127.0.0.1", port, "/echo", "POST", Nil{}, "hello")
    client_score(r)

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
    s : String <- IO.join(String, chan)
    +total : U32 = (a : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 18440)
    main_go(b)

#|1
