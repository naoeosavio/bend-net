# io (httpx_h1_expect): the H1 client must skip interim 1xx responses
# (task-042 phase 4, audit item 6). RFC 9110 section 15.2 lets any number
# of 1xx heads precede the final response: node's writeEarlyHints (103),
# Expect: 100-continue (100) and CDNs produce them, and treating one as
# the answer hands the caller status 100/103 with whatever framing the
# interim head implies.
#
# Each case is a raw one-shot plaintext server on its own listener; the
# client is HTTPX.fetch_insecure (the plaintext H1 lane, x_h1.cli.head):
#   case 1: 100 Continue + 200 OK, body "hello";
#   case 2: 103 Early Hints with a Link header + 200 OK;
#   case 3: 100 Continue + 103 Early Hints + 200 OK (N interim heads).
# Before the fix each case answered the interim head (no body), so the
# score was 000; now every case answers the final 200 with "hello",
# golden 111.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def listen_retry(port: U32, r: Result<&1, &1, (U32 & String), Listener>, rest: IO(Listener & U32)) -> IO(Listener & U32):
  match r:
    case Done{l}:
      IO.pure(Listener & U32, (l, port))
    case Fail{e}:
      rest

def listen_any(tries: Nat, +port: U32) -> IO(Listener & U32):
  match tries:
    case 0n:
      IO.die(Listener & U32, 1, "no free tcp port")
    case 1n+t:
      rest = listen_any(t, (port + 1 : U32))
      do IO<Listener & U32>:
        r : Result<&1, &1, (U32 & String), Listener> <- TCP.listen(port)
        listen_retry(port, r, rest)

# Raw server: read the request, write the canned bytes, close both.
def raw_sent(sent: Socket & Result<&1, &1, (U32 & String), Unit>, l: Listener) -> IO(Unit):
  (s2, r2) = sent
  do IO<Unit>:
    x : Unit <- Socket.close(s2)
    y : Unit <- Listener.close(l)
    return x

def server_drain(m: Socket & Result<&1, &1, (U32 & String), String>, l: Listener, text: String) -> IO(Unit):
  (s, r) = m
  do IO<Unit>:
    sent : Socket & Result<&1, &1, (U32 & String), Unit> <- TCP.send(s, text)
    raw_sent(sent, l)

def server_raw(l: Listener, sock: Socket, text: String) -> IO(Unit):
  do IO<Unit>:
    got : Socket & Result<&1, &1, (U32 & String), String> <- TCP.recv(sock, 8192)
    server_drain(got, l, text)

def server_conn(m: Listener & Result<&1, &1, (U32 & String), Socket>, text: String) -> IO(Unit):
  (l, r) = m
  match r:
    case Fail{e}:
      Listener.close(l)
    case Done{sock}:
      server_raw(l, sock, text)

def server_side(l: Listener, text: String) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, (U32 & String), Socket> <- TCP.accept(l)
    server_conn(m, text)

def body_ok(r: Result<&1, &1, (U32 & String), String>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{body}:
      b2u(String.eq(body, "hello"))

def case_continue(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"))
    r : Result<&1, &1, (U32 & String), String> <- HTTPX.fetch_insecure("http://127.0.0.1:" ++ U32.show(port) ++ "/")
    return body_ok(r)

def case_hints(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l, "HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"))
    r : Result<&1, &1, (U32 & String), String> <- HTTPX.fetch_insecure("http://127.0.0.1:" ++ U32.show(port) ++ "/")
    return body_ok(r)

def case_two(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"))
    r : Result<&1, &1, (U32 & String), String> <- HTTPX.fetch_insecure("http://127.0.0.1:" ++ U32.show(port) ++ "/")
    return body_ok(r)

def main_go(b1: Listener & U32, b2: Listener & U32, b3: Listener & U32) -> IO(U32):
  do IO<U32>:
    a : U32 <- case_continue(b1)
    c : U32 <- case_hints(b2)
    d : U32 <- case_two(b3)
    +total : U32 = (a * 100 + c * 10 + d : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

def main() -> IO(U32):
  do IO<U32>:
    b1 : Listener & U32 <- listen_any(32n, 18571)
    b2 : Listener & U32 <- listen_any(32n, 18571)
    b3 : Listener & U32 <- listen_any(32n, 18571)
    main_go(b1, b2, b3)

#|111
