# HTTPX echo server for node interop (manual only — not in check.sh).
# Serves HTTPX.server.concurrent forever on an ephemeral port (printed
# to stdout for the peer script). No H2 import: pure mini-H2 server.
# Usage: bend examples/httpx/httpx_echoserv.bend -o /tmp/opencode/httpx_echoserv
#        /tmp/opencode/httpx_echoserv   # prints PORT, serves until killed
import Base
import ../../lib/httpx.bend as HTTPX

def echo(req: HTTPX.Request) -> IO(HTTPX.Response):
  match req:
    case HTTPX.Request{+method, +path, +headers, +body}:
      IO.pure(HTTPX.Response, HTTPX.Response{200, Nil{}, body})

law server:
  for l: Listener
  IO(Unit)

def server(l):
  HTTPX.server.concurrent(~echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")

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
  IO(Unit)

def main_go(b):
  (l, port) = b
  do IO<Unit>:
    w : Unit <- IO.print(U32.show(port))
    server(l)

law main:
  IO(Unit)

def main():
  do IO<Unit>:
    b : Listener & U32 <- listen_any(32n, 19892)
    main_go(b)
