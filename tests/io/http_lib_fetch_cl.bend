# lib (http_lib_fetch_cl): fetch framing — Content-Length cuts exactly
# CL bytes, Transfer-Encoding: chunked decodes via unchunk, and a CL
# longer than what arrived (the 64KB cap or early close) fails closed
# with 413. Each case is a raw one-shot server on an ephemeral port.
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

law raw_sent:
  for sent: Socket & Result<&1, &1, (U32 & String), Unit>
  for l: Listener
  IO(Unit)

def raw_sent(sent, l):
  (s2, r2) = sent
  do IO<Unit>:
    x : Unit <- Socket.close(s2)
    y : Unit <- Listener.close(l)
    return x

law server_drain:
  for m: Socket & Result<&1, &1, (U32 & String), String>
  for l: Listener
  for text: String
  IO(Unit)

def server_drain(m, l, text):
  (s, r) = m
  do IO<Unit>:
    sent : Socket & Result<&1, &1, (U32 & String), Unit> <- TCP.send(s, text)
    raw_sent(sent, l)

law server_raw:
  for l: Listener
  for sock: Socket
  for text: String
  IO(Unit)

def server_raw(l, sock, text):
  do IO<Unit>:
    got : Socket & Result<&1, &1, (U32 & String), String> <- TCP.recv(sock, 8192)
    server_drain(got, l, text)

law server_conn:
  for m: Listener & Result<&1, &1, (U32 & String), Socket>
  for text: String
  IO(Unit)

def server_conn(m, text):
  (l, r) = m
  match r:
    case Fail{e}:
      Listener.close(l)
    case Done{sock}:
      server_raw(l, sock, text)

law server_side:
  for l: Listener
  for text: String
  IO(Unit)

def server_side(l, text):
  do IO<Unit>:
    m : Listener & Result<&1, &1, (U32 & String), Socket> <- TCP.accept(l)
    server_conn(m, text)

law chk_sync0:
  for chan: Chan(Unit)
  IO(U32)

def chk_sync0(chan):
  do IO<U32>:
    x : Unit <- IO.join(Unit, chan)
    return 0

law chk_sync_eq:
  for chan: Chan(Unit)
  for body: String
  for want: String
  IO(U32)

def chk_sync_eq(chan, body, want):
  do IO<U32>:
    x : Unit <- IO.join(Unit, chan)
    return b2u(String.eq(body, want))

law chk_eq:
  for chan: Chan(Unit)
  for want: String
  for r: Result<&1, &1, (U32 & String), String>
  IO(U32)

def chk_eq(chan, want, r):
  match r:
    case Fail{e}:
      chk_sync0(chan)
    case Done{body}:
      chk_sync_eq(chan, body, want)

law chk_413:
  for chan: Chan(Unit)
  for code: U32
  for r: Result<&1, &1, (U32 & String), String>
  IO(U32)

def chk_413(chan, code, r):
  match r:
    case Fail{(c, e)}:
      do IO<U32>:
        x : Unit <- IO.join(Unit, chan)
        return b2u(U32.is_eq(c, code))
    case Done{body}:
      do IO<U32>:
        x : Unit <- IO.join(Unit, chan)
        return 0

law case_cl:
  for b: Listener & U32
  IO(U32)

def case_cl(b):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"))
    r : Result<&1, &1, (U32 & String), String> <- HTTP.fetch("http://127.0.0.1:" ++ U32.show(port) ++ "/")
    chk_eq(chan, "hello", r)

law case_chunked:
  for b: Listener & U32
  IO(U32)

def case_chunked(b):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n3\r\n wo\r\n0\r\n\r\n"))
    r : Result<&1, &1, (U32 & String), String> <- HTTP.fetch("http://127.0.0.1:" ++ U32.show(port) ++ "/")
    chk_eq(chan, "hello wo", r)

law case_413:
  for b: Listener & U32
  IO(U32)

def case_413(b):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l, "HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nConnection: close\r\n\r\nsmall"))
    r : Result<&1, &1, (U32 & String), String> <- HTTP.fetch("http://127.0.0.1:" ++ U32.show(port) ++ "/")
    chk_413(chan, 413, r)

law main_go:
  for b1: Listener & U32
  for b2: Listener & U32
  for b3: Listener & U32
  IO(U32)

def main_go(b1, b2, b3):
  do IO<U32>:
    a : U32 <- case_cl(b1)
    c : U32 <- case_chunked(b2)
    d : U32 <- case_413(b3)
    +total : U32 = (a * 100 + c * 10 + d : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b1 : Listener & U32 <- listen_any(32n, 19587)
    b2 : Listener & U32 <- listen_any(32n, 19587)
    b3 : Listener & U32 <- listen_any(32n, 19587)
    main_go(b1, b2, b3)

#|111
