# lib (mux_send_request): String-body requests against mini-H2 server.
# Server is HTTPX.server_on_concurrent echoing the body; client is
# HTTPX.send_request_insecure POST "hello" (String in, String out) plus
# HTTPX.send_request_bytes_insecure (String in, raw bytes out).
# Golden 2 iff both answered bodies are "hello". Covers the textual
# send_request lane (mirror https.send_request) with no http2 import.
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

def client_score_text(+text: String) -> U32:
  b2u(String.eq(text, "hello"))

def client_score(r: Result<&1, &1, U32 & String, String>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+text}:
      client_score_text(text)

def client_score_bytes_body(+body: List<&2, U32>) -> U32:
  b2u(U32.is_eq(HTTPX.x_eq(body, HTTPX.x_str_bytes("hello")), 1))

def client_score_bytes(r: Result<&1, &1, U32 & String, List<&2, U32>>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+body}:
      client_score_bytes_body(body)

def client(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, String> <- HTTPX.send_request_insecure("127.0.0.1", port, "/echo", "POST", Nil{}, "hello")
    rb : Result<&1, &1, U32 & String, List<&2, U32>> <- HTTPX.send_request_bytes_insecure("127.0.0.1", port, "/echo", "POST", Nil{}, HTTPX.x_str_bytes("hello"))
    IO.pure(U32, (client_score(r) + client_score_bytes(rb) : U32))

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

#|2
