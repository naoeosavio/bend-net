# httpx (httpx_h1_upgrade): H1 upgrade on the server lane.
#
# A) once_h1_open lends the socket out: ~H answers 101 (no Content-Length,
# Upgrade/Connection kept), ~K greets one byte down the borrowed socket,
# echoes the client's byte back and closes. The client (h1_open_insecure
# on one connection) must see status 101, the greeting (from rest when the
# writes coalesce, from the socket otherwise) and its echo back. Had the
# 101 fallen back into the keep-alive machine instead of ~K, no greeting
# would ever arrive.
# B) the same lane refusing: ~H answers 200 twice over on_h1_open, and the
# client takes Fail 502 both times — the lane answered, rejoined, saw EOF
# and accepted again.
# C) h1_open.rewrap closes on Fail: over plain TCP, a rewrapped Fail 502
# must read as EOF on the peer (the Phase-2 leak, fixed in Phase 3).
# Golden 7 = 3 (101 + greet + echo) + 2 (502 + 502) + 2 (502 + EOF).
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def up_hs() -> List<&2, HTTP.Hdr>:
  [HTTP.Hdr{"Upgrade", "websocket"}, HTTP.Hdr{"Connection", "Upgrade"}, HTTP.Hdr{"Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="}, HTTP.Hdr{"Sec-WebSocket-Version", "13"}]

def up_h(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{101, [HTTP.Hdr{"Upgrade", "websocket"}, HTTP.Hdr{"Connection", "Upgrade"}, HTTP.Hdr{"Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="}], Nil{}})

def up_k_done(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s2, r2) = sent
  TLS.tls_close(s2)

def up_k_echo(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Unit):
  (s, r) = got
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{+part}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(s, part)
        up_k_done(sent)

def up_k_after(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = sent
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{u}:
      do IO<Unit>:
        got : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s, 16)
        up_k_echo(got)

def up_k(sock: Socket, rest: List<&2, U32>) -> IO(Unit):
  do IO<Unit>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(sock, [5])
    up_k_after(sent)

def cli_echo_got(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: U32) -> IO(U32):
  (s, r) = got
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s)
        IO.pure(U32, acc)
    case Done{+part}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s)
        IO.pure(U32, (acc + HTTP.x_eq(part, [9]) : U32))

def cli_echo_wait(sent: Socket & Result<&1, &1, U32 & String, Unit>, +acc: U32) -> IO(U32):
  (s, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s)
        IO.pure(U32, acc)
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s, 16)
        cli_echo_got(got, acc)

# The greeting rides rest when the two server writes coalesce and the
# socket when they do not — consume rest first either way.
def cli_greet_byte(sock: Socket, +part: List<&2, U32>, +acc: U32) -> IO(U32):
  +acc2 : U32 = (acc + HTTP.x_eq(part, [5]) : U32)
  do IO<U32>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(sock, [9])
    cli_echo_wait(sent, acc2)

def cli_greet_recv(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: U32) -> IO(U32):
  (s, r) = got
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s)
        IO.pure(U32, acc)
    case Done{+part}:
      cli_greet_byte(s, part, acc)

def cli_up_rest(sock: Socket, +rest: List<&2, U32>, +acc: U32) -> IO(U32):
  match rest:
    case Nil{}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16)
        cli_greet_recv(got, acc)
    case h <> t:
      cli_greet_byte(sock, rest, acc)

def cli_up(r: Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>) -> IO(U32):
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{t}:
      (sock, resp, rest) = t
      match resp:
        case HTTP.Response{+status, +headers, +body}:
          +acc : U32 = b2u(U32.is_eq(status, 101))
          cli_up_rest(sock, rest, acc)

def cli_round(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>> <- HTTPX.h1_open_insecure("127.0.0.1", port, HTTP.Request{"GET", "/chat", up_hs(), Nil{}})
    cli_up(r)

def up_side(l: Listener) -> IO(U32):
  do IO<U32>:
    x : Unit <- HTTPX.server.once_h1_open(~up_h, ~up_k, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    IO.pure(U32, 0)

def run_up(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, up_side(l))
    cli_round(port)

def ok_h(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, Nil{}})

# Unreached on the deny lane (anything else answers, never ~K): shut it.
def never_k(sock: Socket, rest: List<&2, U32>) -> IO(Unit):
  TLS.tls_close(sock)

def cli_deny_done(t: Socket & HTTP.Response & List<&2, U32>) -> IO(U32):
  (sock, resp, rest) = t
  do IO<U32>:
    x : Unit <- TLS.tls_close(sock)
    IO.pure(U32, 0)

def cli_deny(r: Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>) -> IO(U32):
  match r:
    case Fail{e}:
      (code, msg) = e
      IO.pure(U32, b2u(U32.is_eq(code, 502)))
    case Done{t}:
      cli_deny_done(t)

def cli_round_deny(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>> <- HTTPX.h1_open_insecure("127.0.0.1", port, HTTP.Request{"GET", "/chat", up_hs(), Nil{}})
    cli_deny(r)

def deny_side(l: Listener) -> IO(U32):
  do IO<U32>:
    x : Unit <- HTTPX.server.on_h1_open(~ok_h, ~never_k, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    IO.pure(U32, 0)

def run_deny(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, deny_side(l))
    +a : U32 <- cli_round_deny(port)
    +b2 : U32 <- cli_round_deny(port)
    IO.pure(U32, (a + b2 : U32))

def cli_rewrap_got(r: Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>) -> IO(U32):
  match r:
    case Fail{e}:
      (code, msg) = e
      IO.pure(U32, b2u(U32.is_eq(code, 502)))
    case Done{t}:
      (sock, resp, rest) = t
      do IO<U32>:
        x : Unit <- Socket.close(sock)
        IO.pure(U32, 0)

def cli_rewrap(conn: Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        r : Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>> <- HTTPX.h1_open.rewrap(~Socket.close, (sock, Fail{(502, "t")}))
        cli_rewrap_got(r)

def peer_eof_got(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(U32):
  (s, r) = got
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        IO.pure(U32, 0)
    case Done{+part}:
      match part:
        case Nil{}:
          do IO<U32>:
            x : Unit <- Socket.close(s)
            IO.pure(U32, 1)
        case h <> t:
          do IO<U32>:
            x : Unit <- Socket.close(s)
            IO.pure(U32, 0)

def peer_eof(conn: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  (l, r) = conn
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TCP.recv_bytes(sock, 16)
        peer_eof_got(got)

# No fork: the connect completes through the listen backlog, so the
# accept below already has its pending connection — and the peer reads
# EOF deterministically after the lane closed.
def run_rewrap(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", port)
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    +a : U32 <- cli_rewrap(conn)
    +p : U32 <- peer_eof(m)
    IO.pure(U32, (a + p : U32))

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

law main:
  IO(U32)

def main():
  do IO<U32>:
    b1 : Listener & U32 <- listen_any(32n, 18522)
    +up : U32 <- run_up(b1)
    b2 : Listener & U32 <- listen_any(32n, 18523)
    +deny : U32 <- run_deny(b2)
    b3 : Listener & U32 <- listen_any(32n, 18524)
    +rw : U32 <- run_rewrap(b3)
    +total : U32 = (up + deny + rw : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|7
