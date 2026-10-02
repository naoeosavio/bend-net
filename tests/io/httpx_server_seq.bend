# lib (lib_httpx_server_seq): sequential server against mini-H2 keep-alive.
# Server is HTTPX.server.on (one stream at a time); client connects once
# (insecure) and POSTs "hi" then "hello" (sids 1,3) on the same TLS
# connection via keep_connect + request. Golden 2 iff both echo with
# status 200 — proves the sequential loop serves past the first stream.
import Base
import ../../lib/tls.bend as TLS
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

def score_one(+want: String, r: Result<&1, &1, U32 & String, HTTPX.Response>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      match resp:
        case HTTPX.Response{+status, +headers, +body}:
          b2u(Bool.and(U32.is_eq(status, 200), U32.is_eq(HTTPX.x_eq(body, HTTPX.x_str_bytes(want)), 1)))

def req2(got: Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt, +s1: U32, +port: U32) -> IO(U32):
  (sock2, r2, st2) = got
  do IO<U32>:
    +s12 : U32 = (s1 + score_one("hello", r2) : U32)
    x : Unit <- TLS.tls_close(sock2)
    IO.pure(U32, s12)

def req1(got: Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt, +port: U32) -> IO(U32):
  (sock1, r1, st1) = got
  do IO<U32>:
    +s1 : U32 = score_one("hi", r1)
    got2 : Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt <- HTTPX.client.request(sock1, st1, "127.0.0.1", port, "POST", "/echo", Nil{}, HTTPX.x_str_bytes("hello"))
    req2(got2, s1, port)

def go_conn(conn: Result<&1, &1, U32 & String, Socket & HTTPX.CliSt>, +port: U32) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock0, st0) = value
      do IO<U32>:
        got1 : Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt <- HTTPX.client.request(sock0, st0, "127.0.0.1", port, "POST", "/echo", Nil{}, HTTPX.x_str_bytes("hi"))
        req1(got1, port)

def client(+port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket & HTTPX.CliSt> <- HTTPX.client.connect_insecure("127.0.0.1", port)
    go_conn(conn, port)

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTPX.server.on(~httpx_echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
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

#|2
