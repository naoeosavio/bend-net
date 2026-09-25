# lib (lib_https_many_streams): twenty clients at once against
# HTTPS.server_on without fuel. The server runs the unbounded accept +
# stream loop; each client is a single-shot insecure POST "hello"
# (same shape as tests/io/https_server_on.bend). Golden 1 iff all 20
# echoed. Client fan-out reuses the fork/join Nat recursion from
# examples/saturate_https_wss.bend (single self-recursive def).
import Base
import ../../lib/tls.bend as TLS
import ../../lib/https.bend as HTTPS
import ../../lib/http2.bend as H2

def h2_echo(req: H2.H2Request) -> IO(H2.H2Response):
  match req:
    case H2.H2Request{+method, +path, +headers, +body}:
      IO.pure(H2.H2Response, H2.H2Response{200, Nil{}, body})

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def client_score(r: Result<&1, &1, (U32 & String), String>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+body}:
      b2u(String.eq(body, "hello"))

law client_one:
  for port: U32
  IO(U32)

def client_one(port):
  do IO<U32>:
    r : Result<&1, &1, (U32 & String), String> <- HTTPS.send_request_insecure("127.0.0.1", port, "/echo", "POST", Nil{}, "hello")
    IO.pure(U32, client_score(r))

law run:
  for port: U32
  for n: Nat
  IO(U32)

def run(port, n):
  match n:
    case 0n:
      IO.pure(U32, 0)
    case 1n+t:
      +p = port
      do IO<U32>:
        chan : Chan(U32) <- IO.fork(U32, client_one(p))
        rest : U32 <- run(p, t)
        a : U32 <- IO.join(U32, chan)
        IO.pure(U32, (a + rest : U32))

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTPS.server_on(~h2_echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
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
    +total : U32 <- run(port, 20n)
    +ok : U32 = b2u(U32.is_eq(total, 20))
    w : Unit <- IO.print(U32.show(ok))
    z : Unit <- IO.die(Unit, 0, "")
    return ok

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 18440)
    main_go(b)

#|1
