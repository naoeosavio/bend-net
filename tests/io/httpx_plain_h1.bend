# httpx (lib_httpx_plain_h1): the plaintext H1 lane ends to end. A
# `http://` URL is only served when the caller says insecure, and the
# server side is server.on_h1_plain (TCP.listen/accept, no cert/key).
# Four requests over the same server, covering both ways into the lane:
# fetch(_bytes)_insecure (GET by URL) and request(_bytes)_plain (any method),
# each once by NAME ("localhost", which the dial must resolve) and once by
# dotted quad (which answers itself). The name cases are the regression guard
# for plain.dial: TCP.connect on a name is EINVAL 22. Golden 4.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def hello_service(req: HTTPX.Request) -> IO(HTTPX.Response):
  match req:
    case HTTPX.Request{method, path, headers, body}:
      IO.pure(HTTPX.Response, HTTPX.Response{200, Nil{}, HTTPX.x_str_bytes("hello")})

def text_ok(r: Result<&1, &1, U32 & String, String>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+body}:
      b2u(String.eq(body, "hello"))

def bytes_ok(r: Result<&1, &1, U32 & String, List<&2, U32>>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+body}:
      b2u(U32.is_eq(HTTPX.x_eq(body, HTTPX.x_str_bytes("hello")), 1))

def client_text(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, String> <-
      HTTPX.fetch_insecure("http://localhost:" ++ U32.show(port) ++ "/hello")
    IO.pure(U32, text_ok(r))

def client_bytes(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, List<&2, U32>> <-
      HTTPX.fetch_bytes_insecure("http://127.0.0.1:" ++ U32.show(port) ++ "/hello")
    IO.pure(U32, bytes_ok(r))

def client_post(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, String> <-
      HTTPX.request_plain("localhost", port, "/hello", "POST", Nil{}, "hi")
    IO.pure(U32, text_ok(r))

def client_post_bytes(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, List<&2, U32>> <-
      HTTPX.request_bytes_plain("127.0.0.1", port, "/hello", "POST", Nil{}, HTTPX.x_str_bytes("hi"))
    IO.pure(U32, bytes_ok(r))

law plain_side:
  for l: Listener
  IO(String)

def plain_side(l):
  do IO<String>:
    x : Unit <- HTTPX.server.on_h1_plain(~hello_service, l)
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
    chan : Chan(String) <- IO.fork(String, plain_side(l))
    +a : U32 <- client_text(port)
    +c : U32 <- client_bytes(port)
    +d : U32 <- client_post(port)
    +e : U32 <- client_post_bytes(port)
    +total : U32 = (a + c + d + e : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 49200)
    x : U32 <- main_go(b)
    return x

#|4
