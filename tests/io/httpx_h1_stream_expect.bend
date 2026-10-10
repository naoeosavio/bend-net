# io (httpx_h1_stream_expect): the streaming H1 client must skip interim
# 1xx heads too (task-042 phase 4b, the lane the phase-4 audit point did
# not cover).
#
# Each case is a raw one-shot plaintext server; the client is
# HTTPX.client.stream_plain with a handler that cancels any head but 200,
# so a 1xx head reaching it ends the stream (Fail 8) and the body never
# arrives:
#   case 1: 103 Early Hints + 200 OK, body "hello";
#   case 2: 100 Continue + 200 OK, body "hello".
# Before the fix the handler saw the interim head and cancelled (score
# 00); now the head is dropped inside the loop and the 200 with its body
# is delivered, golden 11.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# Handler: a non-200 head cancels (so an interim head cannot pass).
def h_status(ok: Bool) -> HTTPX.StreamOut:
  match ok:
    case True{}:
      HTTPX.StreamContinue{}
    case False{}:
      HTTPX.StreamCancel{}

def head_ok(+hd: HTTPX.Head) -> Bool:
  match hd:
    case HTTPX.Head{status, headers}:
      U32.is_eq(status, 200)

def h(ev: HTTPX.StreamEv) -> HTTPX.StreamOut:
  match ev:
    case HTTPX.StreamHead{head}:
      h_status(head_ok(head))
    case HTTPX.StreamData{chunk, fin}:
      HTTPX.StreamContinue{}

def score(r: Result<&1, &1, (U32 & String), (U32 & U32)>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{counts}:
      (total, chunks) = counts
      U32.mul(b2u(U32.is_eq(total, 5)), b2u(U32.is_eq(chunks, 1)))

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

def case_hints(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l, "HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"))
    r : Result<&1, &1, (U32 & String), (U32 & U32)> <- HTTPX.client.stream_plain(~h, "127.0.0.1", port, "GET", "/hints", Nil{}, Nil{})
    return score(r)

def case_continue(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"))
    r : Result<&1, &1, (U32 & String), (U32 & U32)> <- HTTPX.client.stream_plain(~h, "127.0.0.1", port, "GET", "/expect", Nil{}, Nil{})
    return score(r)

def main_go(b1: Listener & U32, b2: Listener & U32) -> IO(U32):
  do IO<U32>:
    a : U32 <- case_hints(b1)
    c : U32 <- case_continue(b2)
    +total : U32 = (a * 10 + c : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

def main() -> IO(U32):
  do IO<U32>:
    b1 : Listener & U32 <- listen_any(32n, 18572)
    b2 : Listener & U32 <- listen_any(32n, 18572)
    main_go(b1, b2)

#|11
