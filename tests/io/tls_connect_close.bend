# lib (lib_tls_connect_close): TLS handshake over loopback (insecure,
# self-signed) plus fail-closed paths. The server accepts one TLS
# connection with the test cert/key, echoes 5 bytes; the client sends
# "hello" and checks the echo. Port 0 dies in validation (611) and a
# refused port dies in dial (612), both without a handshake.
import Base
import ../../lib/tls.bend as TLS

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

law bytes_eq:
  for a: List<&2, U32>
  for b: List<&2, U32>
  U32

def bytes_eq(a, b):
  match a b:
    case Nil{} Nil{}:
      1
    case h1 <> t1 h2 <> t2:
      (b2u(U32.is_eq(h1, h2)) * bytes_eq(t1, t2) : U32)
    case _ _:
      0

law hello_bytes:
  List<&2, U32>

def hello_bytes():
  [104, 101, 108, 108, 111]

law score_echo:
  for r: Result<&1, &1, (U32 & String), List<&2, U32>>
  U32

def score_echo(r):
  match r:
    case Fail{e}:
      0
    case Done{bs}:
      bytes_eq(bs, hello_bytes())

law is_fail:
  for r: Result<&1, &1, (U32 & String), Socket>
  U32

def is_fail(r):
  match r:
    case Fail{e}:
      1
    case Done{s}:
      0

law server_down:
  for l: Listener
  for e: U32 & String
  IO(String)

def server_down(l, e):
  do IO<String>:
    x : Unit <- Listener.close(l)
    return "down"

law server_echo_done:
  for l: Listener
  for sent: Socket & Result<&1, &1, (U32 & String), Unit>
  IO(String)

def server_echo_done(l, sent):
  (s2, r) = sent
  do IO<String>:
    x : Unit <- TLS.tls_close(s2)
    y : Unit <- Listener.close(l)
    return "up"

law server_echo:
  for l: Listener
  for got: Socket & Result<&1, &1, (U32 & String), List<&2, U32>>
  IO(String)

def server_echo(l, got):
  (s2, r) = got
  match r:
    case Fail{e}:
      do IO<String>:
        x : Unit <- TLS.tls_close(s2)
        server_down(l, e)
    case Done{bs}:
      do IO<String>:
        sent : Socket & Result<&1, &1, (U32 & String), Unit> <- TLS.tls_send_bytes(s2, bs)
        server_echo_done(l, sent)

law server_talk:
  for l: Listener
  for sock: Socket
  IO(String)

def server_talk(l, sock):
  do IO<String>:
    got : Socket & Result<&1, &1, (U32 & String), List<&2, U32>> <- TLS.tls_recv_bytes(sock, 8)
    server_echo(l, got)

law server_conn:
  for m: Listener & Result<&1, &1, (U32 & String), Socket>
  IO(String)

def server_conn(m):
  (l, r) = m
  match r:
    case Fail{e}:
      server_down(l, e)
    case Done{sock}:
      server_talk(l, sock)

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    m : Listener & Result<&1, &1, (U32 & String), Socket> <- TLS.tls_accept(l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    server_conn(m)

law client_done:
  for got: Socket & Result<&1, &1, (U32 & String), List<&2, U32>>
  IO(U32)

def client_done(got):
  (s2, r) = got
  do IO<U32>:
    x : Unit <- TLS.tls_close(s2)
    return score_echo(r)

law client_recv:
  for s: Socket
  IO(U32)

def client_recv(s):
  do IO<U32>:
    got : Socket & Result<&1, &1, (U32 & String), List<&2, U32>> <- TLS.tls_recv_bytes(s, 8)
    client_done(got)

law client_sent:
  for sent: Socket & Result<&1, &1, (U32 & String), Unit>
  IO(U32)

def client_sent(sent):
  (s2, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s2)
        return 0
    case Done{u}:
      client_recv(s2)

law client_conn:
  for conn: Result<&1, &1, (U32 & String), Socket>
  IO(U32)

def client_conn(conn):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, (U32 & String), Unit> <- TLS.tls_send_bytes(sock, hello_bytes())
        client_sent(sent)

law client:
  for port: U32
  IO(U32)

def client(port):
  do IO<U32>:
    conn : Result<&1, &1, (U32 & String), Socket> <- TLS.tls_connect_insecure("127.0.0.1", port)
    client_conn(conn)

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
    rb : Result<&1, &1, (U32 & String), Socket> <- TLS.tls_connect_insecure("127.0.0.1", 0)
    rc : Result<&1, &1, (U32 & String), Socket> <- TLS.tls_connect_insecure("127.0.0.1", 1)
    +total : U32 = (a * 100 + is_fail(rb) * 10 + is_fail(rc) : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 19587)
    main_go(b)

#|111
