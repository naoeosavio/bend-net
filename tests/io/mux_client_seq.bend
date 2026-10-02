# lib (lib_mux_client_seq): sequential batch entry against mini-H2 server.
# Server echoes bodies; client is HTTPX.client.on_insecure with 3 requests
# ("hello-0/1/2") on one dial (sids 1,3,5), answers back in request
# order. Golden 3 (one per echo body, order-insensitive sum like the
# concurrent golden).
import Base
import ../../lib/httpx.bend as HTTPX

def mux_echo(req: HTTPX.Request) -> IO(HTTPX.Response):
  match req:
    case HTTPX.Request{+method, +path, +headers, +body}:
      IO.pure(HTTPX.Response, HTTPX.Response{200, Nil{}, body})

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def is_want(+body: List<&2, U32>) -> Bool:
  Bool.or(Bool.or(U32.is_eq(HTTPX.x_eq(body, HTTPX.x_str_bytes("hello-0")), 1), U32.is_eq(HTTPX.x_eq(body, HTTPX.x_str_bytes("hello-1")), 1)), U32.is_eq(HTTPX.x_eq(body, HTTPX.x_str_bytes("hello-2")), 1))

def hit(+resp: HTTPX.Response) -> U32:
  match resp:
    case HTTPX.Response{+status, +headers, +body}:
      b2u(Bool.and(U32.is_eq(status, 200), is_want(body)))

def total(rs: List<&2, HTTPX.Response>) -> U32:
  match rs:
    case Nil{}:
      0
    case +h <> t:
      (hit(h) + total(t) : U32)

def reqs() -> List<&2, HTTPX.Request>:
  [HTTPX.Request{"POST", "/echo", Nil{}, HTTPX.x_str_bytes("hello-0")}, HTTPX.Request{"POST", "/echo", Nil{}, HTTPX.x_str_bytes("hello-1")}, HTTPX.Request{"POST", "/echo", Nil{}, HTTPX.x_str_bytes("hello-2")}]

def client_score(r: Result<&1, &1, U32 & String, List<&2, HTTPX.Response>>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+rs}:
      total(rs)

def client(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, List<&2, HTTPX.Response>> <- HTTPX.client.on_insecure("127.0.0.1", port, reqs())
    IO.pure(U32, client_score(r))

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTPX.server_on_concurrent(~mux_echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
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

#|3
