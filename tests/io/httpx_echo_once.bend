# httpx (lib_httpx_echo_once): the one-shot server and the fixed echo
# server. server.once accepts one connection and stops (no recursion), and
# server.echo is the fixed 200+body handler — both TASK-026 Phase 7
# entries. Client side uses the matching one-shots (client.once_insecure
# and client.echo_insecure).
#
# Two scenarios on two listeners: A) server.once with the test's own echo
# handler, POST "hello" through client.once_insecure; B) server.echo, GET
# through client.echo_insecure (empty body back). Golden 2 (one per
# scenario).
import Base
import ../../lib/tcp.bend as TCP
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

def status_body_is(+resp: HTTPX.Response, want: U32, expected: List<&2, U32>) -> U32:
  match resp:
    case HTTPX.Response{+status, +headers, +body}:
      b2u(Bool.and(U32.is_eq(status, want), U32.is_eq(HTTPX.x_eq(body, expected), 1)))

def once_score(r: Result<&1, &1, U32 & String, HTTPX.Response>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      status_body_is(resp, 200, HTTPX.x_str_bytes("hello"))

def echo_score(r: Result<&1, &1, U32 & String, HTTPX.Response>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      status_body_is(resp, 200, Nil{})

def once_client(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTPX.Response> <-
      HTTPX.client.once_insecure("127.0.0.1", port, HTTPX.Request{"POST", "/echo", Nil{}, HTTPX.x_str_bytes("hello")})
    IO.pure(U32, once_score(r))

def echo_client(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTPX.Response> <-
      HTTPX.client.echo_insecure("127.0.0.1", port, "/echo")
    IO.pure(U32, echo_score(r))

law once_side:
  for l: Listener
  IO(String)

def once_side(l):
  do IO<String>:
    x : Unit <- HTTPX.server.once(~httpx_echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    return "up"

law echo_side:
  for l: Listener
  IO(String)

def echo_side(l):
  do IO<String>:
    x : Unit <- HTTPX.server.echo(l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
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
  for b2: Listener & U32
  IO(U32)

def main_go(b, b2):
  (l, port) = b
  (l2, port2) = b2
  do IO<U32>:
    c1 : Chan(String) <- IO.fork(String, once_side(l))
    c2 : Chan(String) <- IO.fork(String, echo_side(l2))
    +a : U32 <- once_client(port)
    +c : U32 <- echo_client(port2)
    +total : U32 = (a + c : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 49000)
    b2 : Listener & U32 <- listen_any(32n, 49100)
    x : U32 <- main_go(b, b2)
    return x

#|2
