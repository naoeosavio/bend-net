# lib (lib_httpx_client_concurrent): pipelined N=4 POSTs on one TLS+H2
# connection against HTTPX.server.concurrent. Client sends 4 requests
# (sids 1,3,5,7) back-to-back, then drains 4 responses in any order
# via slots (no per-sid sequential wait). Handler scores 1 per echo
# body in hello-0..3. Golden 4 (sum).
import Base
import ../../lib/tls.bend as TLS
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

def is_want(+body: List<&2, U32>) -> Bool:
  Bool.or(Bool.or(U32.is_eq(HTTP.x_eq(body, HTTP.x_str_bytes("hello-0")), 1), U32.is_eq(HTTP.x_eq(body, HTTP.x_str_bytes("hello-1")), 1)), Bool.or(U32.is_eq(HTTP.x_eq(body, HTTP.x_str_bytes("hello-2")), 1), U32.is_eq(HTTP.x_eq(body, HTTP.x_str_bytes("hello-3")), 1)))

def h(resp: HTTP.Response) -> U32:
  match resp:
    case HTTP.Response{+status, +headers, +body}:
      b2u(Bool.and(U32.is_eq(status, 200), is_want(body)))

def reqs() -> List<&2, HTTP.Request>:
  [HTTP.Request{"POST", "/echo", Nil{}, HTTP.x_str_bytes("hello-0")}, HTTP.Request{"POST", "/echo", Nil{}, HTTP.x_str_bytes("hello-1")}, HTTP.Request{"POST", "/echo", Nil{}, HTTP.x_str_bytes("hello-2")}, HTTP.Request{"POST", "/echo", Nil{}, HTTP.x_str_bytes("hello-3")}]

def client_score(r: Result<&1, &1, U32 & String, U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+total}:
      total

def client(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32> <- HTTPX.client.concurrent_insecure(~h, "127.0.0.1", port, reqs())
    IO.pure(U32, client_score(r))

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTPX.server.concurrent(~httpx_echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
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
    w : Unit <- IO.print(U32.show(a))
    z : Unit <- IO.die(Unit, 0, "")
    return a

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 18440)
    main_go(b)

#|4
