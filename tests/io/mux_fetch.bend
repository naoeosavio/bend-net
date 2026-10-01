# lib (lib_mux_fetch): fetch by URL against the mini-H2 httpx (Phase 9).
# Server answers every request 200 "hello"; client is
# HTTPX.fetch_insecure("https://127.0.0.1:port/hello") (GET by URL through
# httpx_url.read_url, no http import). Golden 1 iff the body comes back
# as the String "hello".
import Base
import ../../lib/httpx.bend as HTTPX

def mux_hello(req: HTTPX.Request) -> IO(HTTPX.Response):
  match req:
    case HTTPX.Request{+method, +path, +headers, +body}:
      IO.pure(HTTPX.Response, HTTPX.Response{200, Nil{}, HTTPX.x_str_bytes("hello")})

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def client_score(r: Result<&1, &1, U32 & String, String>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{body}:
      b2u(String.eq(body, "hello"))

def client_url(+port: U32) -> String:
  "https://127.0.0.1:" ++ U32.show(port) ++ "/hello"

def client(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, String> <- HTTPX.fetch_insecure(client_url(port))
    IO.pure(U32, client_score(r))

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTPX.server_on_concurrent(~mux_hello, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
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
    b : Listener & U32 <- listen_any(32n, 18440)
    main_go(b)

#|1
