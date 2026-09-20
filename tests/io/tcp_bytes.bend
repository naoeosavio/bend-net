# lib (lib_tcp_bytes): TCP.send_bytes / TCP.recv_bytes over loopback.
# The server accepts one connection, receives a short frame, and echoes
# a fixed three-byte pattern; the client first sends a byte past 255
# (refused with EINVAL before the net), then a valid frame, and checks
# the echo. Both effects hand the socket back on every path.
import Base
import ../../lib/tcp.bend as TCP
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

law score:
  for r: Result<&1, &1, (U32 & String), List<&2, U32>>
  U32

def score(r):
  match r:
    case Done{bs}:
      b2u(String.eq(HTTP.to_string(bs), "hij"))
    case Fail{e}:
      0

law echo_bytes:
  List<&2, U32>

def echo_bytes():
  [104, 105, 106]

law close_all:
  for l: Listener
  for s: Socket
  IO(String)

def close_all(l, s):
  do IO<String>:
    x : Unit <- Socket.close(s)
    y : Unit <- Listener.close(l)
    return "up"

law send_back:
  for l: Listener
  for r: Socket & Result<&1, &1, (U32 & String), Unit>
  IO(String)

def send_back(l, r):
  (s2, got) = r
  close_all(l, s2)

law after_recv:
  for l: Listener
  for r: Socket & Result<&1, &1, (U32 & String), List<&2, U32>>
  IO(String)

def after_recv(l, r):
  (s2, got) = r
  do IO<String>:
    sent : Socket & Result<&1, &1, (U32 & String), Unit> <- TCP.send_bytes(s2, echo_bytes())
    send_back(l, sent)

law server_talk:
  for l: Listener
  for sock: Socket
  IO(String)

def server_talk(l, sock):
  do IO<String>:
    r : Socket & Result<&1, &1, (U32 & String), List<&2, U32>> <- TCP.recv_bytes(sock, 8)
    after_recv(l, r)

law server_down:
  for l: Listener
  for e: U32 & String
  IO(String)

def server_down(l, e):
  do IO<String>:
    x : Unit <- Listener.close(l)
    return "down"

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
    m : Listener & Result<&1, &1, (U32 & String), Socket> <- TCP.accept(l)
    server_conn(m)

law client_done:
  for got: Socket & Result<&1, &1, (U32 & String), List<&2, U32>>
  for acc: U32
  IO(U32)

def client_done(got, acc):
  (s2, r) = got
  do IO<U32>:
    x : Unit <- Socket.close(s2)
    return (score(r) * 10 + acc : U32)

law client_recv:
  for s: Socket
  for acc: U32
  IO(U32)

def client_recv(s, acc):
  do IO<U32>:
    got : Socket & Result<&1, &1, (U32 & String), List<&2, U32>> <- TCP.recv_bytes(s, 8)
    client_done(got, acc)

law client_sent:
  for sent: Socket & Result<&1, &1, (U32 & String), Unit>
  for acc: U32
  IO(U32)

def client_sent(sent, acc):
  (s2, r) = sent
  match r:
    case Fail{e}:
      IO.die(U32, 1, "client send failed")
    case Done{u}:
      client_recv(s2, acc)

law client_send_ok:
  for sock: Socket
  for acc: U32
  IO(U32)

def client_send_ok(sock, acc):
  do IO<U32>:
    sent : Socket & Result<&1, &1, (U32 & String), Unit> <- TCP.send_bytes(sock, echo_bytes())
    client_sent(sent, acc)

law client_bad_code:
  for s: Socket
  for code: U32
  IO(U32)

def client_bad_code(s, code):
  client_send_ok(s, b2u(U32.is_eq(code, 22)))

law client_bad_done:
  for bad: Socket & Result<&1, &1, (U32 & String), Unit>
  IO(U32)

def client_bad_done(bad):
  (s2, r) = bad
  match r:
    case Fail{(code, msg)}:
      client_bad_code(s2, code)
    case Done{u}:
      IO.die(U32, 2, "expected EINVAL")

law client_bad:
  for sock: Socket
  IO(U32)

def client_bad(sock):
  do IO<U32>:
    bad : Socket & Result<&1, &1, (U32 & String), Unit> <- TCP.send_bytes(sock, [256])
    client_bad_done(bad)

law client_conn:
  for conn: Result<&1, &1, (U32 & String), Socket>
  IO(U32)

def client_conn(conn):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      client_bad(sock)

law client:
  for port: U32
  IO(U32)

def client(port):
  do IO<U32>:
    conn : Result<&1, &1, (U32 & String), Socket> <- TCP.connect("127.0.0.1", port)
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
    +n : U32 <- client(port)
    s : String <- IO.join(String, chan)
    w : Unit <- IO.print(U32.show(n))
    return n

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 19587)
    main_go(b)

#|11
