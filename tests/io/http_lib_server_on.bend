# lib (http_lib_server_on): server_on — the generic keep-alive server.
# One connection serves GET /a, then POST /b with a body, then a
# Connection: close request; the client reads each response on the same
# socket and confirms the server closed after the third.
import Base
import ../../lib/http.bend as HTTP

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

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

law h.handler:
  for m: String
  for p: String
  for hd: List<&2, HTTP.Hdr>
  for b: String
  IO(U32 & List<&1, (String & String)> & String)

def h.handler(m, p, hd, b):
  IO.pure(U32 & List<&1, (String & String)> & String, (200, [], p ++ ":" ++ b))

law server_side:
  for l: Listener
  IO(Unit)

def server_side(l):
  do IO<Unit>:
    z : Unit <- HTTP.server_on(~h.handler, l)
    return z

law cli.dead:
  for s: Socket
  IO(U32)

def cli.dead(s):
  do IO<U32>:
    x : Unit <- Socket.close(s)
    return 0

law cli.eof:
  for m: Socket & Result<&1, &1, (U32 & String), String>
  for a: U32
  for b: U32
  for c: U32
  IO(U32)

def cli.eof(m, a, b, c):
  (s, r) = m
  match r:
    case Fail{e}:
      cli.dead(s)
    case Done{part}:
      d = b2u(String.is_empty(part))
      do IO<U32>:
        x : Unit <- Socket.close(s)
        +total : U32 = (a * 100 + b * 10 + c * d : U32)
        w : Unit <- IO.print(U32.show(total))
        z : Unit <- IO.die(Unit, 0, "")
        return total

law cli.got3:
  for m: Socket & Result<&1, &1, (U32 & String), String>
  for a: U32
  for b: U32
  IO(U32)

def cli.got3(m, a, b):
  (s, r) = m
  match r:
    case Fail{e}:
      cli.dead(s)
    case Done{part}:
      do IO<U32>:
        r1 : Socket & Result<&1, &1, (U32 & String), String> <- TCP.recv(s, 8192)
        cli.eof(r1, a, b, b2u(String.eq(HTTP.body_of(part), "/c:")))

law cli.sent3:
  for m: Socket & Result<&1, &1, (U32 & String), Unit>
  for a: U32
  for b: U32
  IO(U32)

def cli.sent3(m, a, b):
  (s, r) = m
  match r:
    case Fail{e}:
      cli.dead(s)
    case Done{u}:
      do IO<U32>:
        r1 : Socket & Result<&1, &1, (U32 & String), String> <- TCP.recv(s, 8192)
        cli.got3(r1, a, b)

law cli.req3:
  for s: Socket
  for a: U32
  for b: U32
  IO(U32)

def cli.req3(s, a, b):
  do IO<U32>:
    m : Socket & Result<&1, &1, (U32 & String), Unit> <- TCP.send(s, "GET /c HTTP/1.1\r\nConnection: close\r\n\r\n")
    cli.sent3(m, a, b)

law cli.got2:
  for m: Socket & Result<&1, &1, (U32 & String), String>
  for a: U32
  IO(U32)

def cli.got2(m, a):
  (s, r) = m
  match r:
    case Fail{e}:
      cli.dead(s)
    case Done{part}:
      cli.req3(s, a, b2u(String.eq(HTTP.body_of(part), "/b:xyz")))

law cli.sent2:
  for m: Socket & Result<&1, &1, (U32 & String), Unit>
  for a: U32
  IO(U32)

def cli.sent2(m, a):
  (s, r) = m
  match r:
    case Fail{e}:
      cli.dead(s)
    case Done{u}:
      do IO<U32>:
        r1 : Socket & Result<&1, &1, (U32 & String), String> <- TCP.recv(s, 8192)
        cli.got2(r1, a)

law cli.req2:
  for s: Socket
  for a: U32
  IO(U32)

def cli.req2(s, a):
  do IO<U32>:
    m : Socket & Result<&1, &1, (U32 & String), Unit> <- TCP.send(s, "POST /b HTTP/1.1\r\nContent-Length: 3\r\n\r\nxyz")
    cli.sent2(m, a)

law cli.got1:
  for m: Socket & Result<&1, &1, (U32 & String), String>
  IO(U32)

def cli.got1(m):
  (s, r) = m
  match r:
    case Fail{e}:
      cli.dead(s)
    case Done{part}:
      cli.req2(s, b2u(String.eq(HTTP.body_of(part), "/a:")))

law cli.sent1:
  for m: Socket & Result<&1, &1, (U32 & String), Unit>
  IO(U32)

def cli.sent1(m):
  (s, r) = m
  match r:
    case Fail{e}:
      cli.dead(s)
    case Done{u}:
      do IO<U32>:
        r1 : Socket & Result<&1, &1, (U32 & String), String> <- TCP.recv(s, 8192)
        cli.got1(r1)

law cli.open:
  for conn: Result<&1, &1, (U32 & String), Socket>
  IO(U32)

def cli.open(conn):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        m : Socket & Result<&1, &1, (U32 & String), Unit> <- TCP.send(sock, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n")
        cli.sent1(m)

law main_go:
  for b: Listener & U32
  IO(U32)

def main_go(b):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l))
    conn : Result<&1, &1, (U32 & String), Socket> <- TCP.connect("127.0.0.1", port)
    cli.open(conn)

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 19587)
    main_go(b)

#|111
