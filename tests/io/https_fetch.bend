# lib (lib_https_fetch): HTTPS facade loopback. The server accepts one
# TLS connection and serves streams with the echo handler via
# HTTPS.serve_start; the client POSTs "hello" with
# HTTPS.send_request_insecure and checks the echo. Golden 1.
import Base
import ../../lib/tls.bend as TLS
import ../../lib/https.bend as HTTPS
import ../../lib/http2.bend as H2

def h2_echo(req: H2.H2Request) -> IO(H2.H2Response):
  match req:
    case H2.H2Request{+method, +path, +headers, +body}:
      IO.pure(H2.H2Response, H2.H2Response{200, Nil{}, body})

def is_hello.go(same: Bool) -> U32:
  match same:
    case True{}:
      1
    case False{}:
      0

def is_hello(s: String) -> U32:
  is_hello.go(String.eq(s, "hello"))

law server_down:
  for l: Listener
  for e: U32 & String
  IO(String)

def server_down(l, e):
  do IO<String>:
    x : Unit <- Listener.close(l)
    return "down"

def server_close(l: Listener) -> IO(String):
  do IO<String>:
    y : Unit <- Listener.close(l)
    return "up"

def server_served(l: Listener, sock: Socket) -> IO(String):
  do IO<String>:
    x : Unit <- HTTPS.serve_start(~h2_echo, sock, 8n)
    server_close(l)

def server_conn(m: Listener & Result<&1, &1, (U32 & String), Socket>) -> IO(String):
  (l, r) = m
  match r:
    case Fail{e}:
      server_down(l, e)
    case Done{sock}:
      server_served(l, sock)

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    m : Listener & Result<&1, &1, (U32 & String), Socket> <- TLS.tls_accept(l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    server_conn(m)

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
    r : Result<&1, &1, (U32 & String), String> <- HTTPS.send_request_insecure("127.0.0.1", port, "/echo", "POST", Nil{}, "hello")
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
