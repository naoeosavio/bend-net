# io (io_tcp_bytes_loopback): TCP.send_bytes/TCP.recv_bytes carry bytes
# as they are, 0..255 one List cell each, where TCP.send/TCP.recv encode
# and decode UTF-8. The client sends all 256 byte values, the server
# checks them exact and echoes the same list back, and the client checks
# the echo exact: two lanes, one line each. Handles are affine, so every
# op threads its handle back OUTSIDE the Result -- no path can lose it --
# and each tuple destructures in its own helper (a destructure cannot
# ride a do line). The listener retries upward from a base port on Fail:
# the fallback action is built before the attempt, so the retry is a
# plain value and the recursion is a structural descent on tries (+port
# licenses the port's reuse).
import Base
import ../../lib/tcp.bend as TCP

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

law eq_list:
  for xs: List<&2, U32>
  for ys: List<&2, U32>
  U32

def eq_list(xs, ys):
  match xs:
    case Nil{}:
      match ys:
        case Nil{}:
          1
        case _ <> _:
          0
    case h1 <> t1:
      match ys:
        case Nil{}:
          0
        case h2 <> t2:
          (b2u(U32.is_eq(h1, h2)) * eq_list(t1, t2) : U32)

law bytes_go:
  for +n: Nat
  for acc: List<&2, U32>
  List<&2, U32>

def bytes_go(n, acc):
  match n:
    case 0n:
      acc
    case 1n+p:
      bytes_go(p, U32.from_nat(p) <> acc)

law all_bytes:
  List<&2, U32>

def all_bytes():
  bytes_go(256n, Nil{})

law step_finish:
  for l: Listener
  for a: Socket
  for s1: U32
  for m: Socket & Result<&1, &1, (U32 & String), List<&2, U32>>
  IO(U32)

def step_finish(l, a, s1, m):
  (c3, r2) = m
  do IO<U32>:
    ys : List<&2, U32> <- IO.pass(List<&2, U32>, r2)
    s2 : U32 <- IO.pure(U32, eq_list(ys, all_bytes()))
    p  : Unit <- IO.print(U32.show(s1))
    q  : Unit <- IO.print(U32.show(s2))
    x  : Unit <- Socket.close(c3)
    y  : Unit <- Socket.close(a)
    z  : Unit <- Listener.close(l)
    return 0

law echo_done:
  for l: Listener
  for c: Socket
  for s1: U32
  for m: Socket & Result<&1, &1, (U32 & String), Unit>
  IO(U32)

def echo_done(l, c, s1, m):
  (a3, r) = m
  do IO<U32>:
    u  : Unit <- IO.pass(Unit, r)
    m2 : Socket & Result<&1, &1, (U32 & String), List<&2, U32>> <-
      TCP.recv_bytes(c, 1024)
    step_finish(l, a3, s1, m2)

law recv_done:
  for l: Listener
  for c: Socket
  for m: Socket & Result<&1, &1, (U32 & String), List<&2, U32>>
  IO(U32)

def recv_done(l, c, m):
  (a2, r) = m
  do IO<U32>:
    xs : List<&2, U32> <- IO.pass(List<&2, U32>, r)
    s1 : U32 <- IO.pure(U32, eq_list(xs, all_bytes()))
    em : Socket & Result<&1, &1, (U32 & String), Unit> <-
      TCP.send_bytes(a2, all_bytes())
    echo_done(l, c, s1, em)

law send_done:
  for l: Listener
  for a: Socket
  for m: Socket & Result<&1, &1, (U32 & String), Unit>
  IO(U32)

def send_done(l, a, m):
  (c2, r) = m
  do IO<U32>:
    u  : Unit <- IO.pass(Unit, r)
    rm : Socket & Result<&1, &1, (U32 & String), List<&2, U32>> <-
      TCP.recv_bytes(a, 1024)
    recv_done(l, c2, rm)

law step_accept:
  for c: Socket
  for p: Listener & Result<&1, &1, (U32 & String), Socket>
  IO(U32)

def step_accept(c, p):
  (l, ar) = p
  do IO<U32>:
    a  : Socket <- IO.pass(Socket, ar)
    sm : Socket & Result<&1, &1, (U32 & String), Unit> <-
      TCP.send_bytes(c, all_bytes())
    send_done(l, a, sm)

law main_go:
  for b: Listener & U32
  IO(U32)

def main_go(b):
  (l, port) = b
  do IO<U32>:
    c : Socket <- IO.try(Socket, TCP.connect("127.0.0.1", port))
    p : Listener & Result<&1, &1, (U32 & String), Socket> <- TCP.accept(l)
    step_accept(c, p)

law tcp_retry:
  for port : U32
  for r    : Result<&1, &1, (U32 & String), Listener>
  for rest : IO(Listener & U32)
  IO(Listener & U32)

def tcp_retry(port, r, rest):
  match r:
    case Done{l}:
      IO.pure(Listener & U32, (l, port))
    case Fail{e}:
      rest

law tcp_listen_any:
  for tries : Nat
  for +port : U32
  IO(Listener & U32)

def tcp_listen_any(tries, port):
  match tries:
    case 0n:
      IO.die(Listener & U32, 1, "no free tcp port")
    case 1n+t:
      rest = tcp_listen_any(t, (port + 1 : U32))
      do IO<Listener & U32>:
        r : Result<&1, &1, (U32 & String), Listener> <- TCP.listen(port)
        tcp_retry(port, r, rest)

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- tcp_listen_any(32n, 19680)
    main_go(b)

#|1
#|1
