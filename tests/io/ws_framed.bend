# io (ws_framed): TCP.recv_frame isolates one WS frame per call over a
# real loopback. The server sends "Hi" in two TCP writes (one byte,
# then a sleep, then the rest: split arrival) plus a ping, "yo" and a
# binary frame in a single write (glued arrival). The client proves
# all four: the split "Hi" reassembles, the glued ping splits off its
# frame, the threaded rest delivers "yo", and the binary payload with
# bytes above 127 roundtrips exact (the UTF-8 String lane would
# corrupt every one of them: 0x89 decodes to U+FFFD on recv,
# [137,130] encodes to four bytes on send). Single-shot recv fails
# this script: the first read holds one byte and the glued read holds
# three frames. Handles are affine, so every op threads its handle
# back OUTSIDE the Result, and each tuple destructures in its own
# helper. The listener retries upward from a base port on Fail.
import Base
import ../../lib/ws.bend as WS

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

law expect_frame:
  for fin: Bool
  for +op: U32
  for +pay: List<&2, U32>
  for want_op: U32
  for +want: List<&2, U32>
  Bool

def expect_frame(fin, op, pay, want_op, want):
  Bool.and(fin, Bool.and(U32.is_eq(op, want_op), U32.is_eq(eq_list(pay, want), 1)))

law unwrap:
  for r: Result<&1, &1, U32 & String, List<&2, U32>>
  List<&2, U32>

def unwrap(r):
  match r:
    case Fail{e}:
      [255]
    case Done{bs}:
      bs

law hi_part1:
  List<&2, U32>

def hi_part1():
  [129]

law hi_part2:
  List<&2, U32>

def hi_part2():
  [2, 72, 105]

law bin_pay:
  List<&2, U32>

def bin_pay():
  [0, 144, 255, 137, 130, 72]

law glued:
  List<&2, U32>

def glued():
  List.append(&2, U32, unwrap(WS.show_frame(True{}, 9, [112, 51])), List.append(&2, U32, unwrap(WS.show_frame(True{}, 1, [121, 111])), unwrap(WS.show_frame(True{}, 2, bin_pay()))))

law finish:
  for s: Socket
  for l: Listener
  for +score: U32
  IO(U32)

def finish(s, l, score):
  do IO<U32>:
    x : Unit <- Socket.close(s)
    y : Unit <- Listener.close(l)
    p : Unit <- IO.print(U32.show(score))
    return score

law bin_got:
  for m: Socket & Result<&1, &1, U32 & String, WS.WSMessage> & List<&2, U32>
  for score: U32
  for l: Listener
  IO(U32)

def bin_got(m, score, l):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      finish(s, l, score)
    case Done{msg}:
      match msg:
        case WS.WSText{text}:
          finish(s, l, score)
        case WS.WSBin{data}:
          finish(s, l, (score + eq_list(data, bin_pay()) : U32))

law yo_checked:
  for ok: Bool
  for s: Socket
  for buf: List<&2, U32>
  for score: U32
  for l: Listener
  IO(U32)

def yo_checked(ok, s, buf, score, l):
  match ok:
    case True{}:
      do IO<U32>:
        m4 : Socket & Result<&1, &1, U32 & String, WS.WSMessage> & List<&2, U32> <- WS.recv_msg_client_framed(s, buf)
        bin_got(m4, (score + 1 : U32), l)
    case False{}:
      finish(s, l, score)

law yo_got:
  for m: Socket & Result<&1, &1, U32 & String, WS.WSMessage> & List<&2, U32>
  for score: U32
  for l: Listener
  IO(U32)

def yo_got(m, score, l):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      finish(s, l, score)
    case Done{msg}:
      match msg:
        case WS.WSText{text}:
          yo_checked(String.eq(text, "yo"), s, rest, score, l)
        case WS.WSBin{data}:
          finish(s, l, score)

law ping_checked:
  for ok: Bool
  for s: Socket
  for +rest: List<&2, U32>
  for score: U32
  for l: Listener
  IO(U32)

def ping_checked(ok, s, rest, score, l):
  match ok:
    case True{}:
      do IO<U32>:
        m3 : Socket & Result<&1, &1, U32 & String, WS.WSMessage> & List<&2, U32> <- WS.recv_msg_client_framed(s, rest)
        yo_got(m3, (score + 1 : U32), l)
    case False{}:
      finish(s, l, score)

law ping_got:
  for m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>
  for score: U32
  for l: Listener
  IO(U32)

def ping_got(m, score, l):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      finish(s, l, score)
    case Done{t}:
      (fin, op, pay) = t
      ping_checked(expect_frame(fin, op, pay, 9, [112, 51]), s, rest, score, l)

law hi_checked:
  for ok: Bool
  for s: Socket
  for +rest: List<&2, U32>
  for score: U32
  for l: Listener
  IO(U32)

def hi_checked(ok, s, rest, score, l):
  match ok:
    case True{}:
      do IO<U32>:
        m2 : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- WS.recv_op_client_framed(s, rest)
        ping_got(m2, (score + 1 : U32), l)
    case False{}:
      finish(s, l, score)

law hi_got:
  for m: Socket & Result<&1, &1, U32 & String, WS.WSMessage> & List<&2, U32>
  for score: U32
  for l: Listener
  IO(U32)

def hi_got(m, score, l):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      finish(s, l, score)
    case Done{msg}:
      match msg:
        case WS.WSText{text}:
          hi_checked(String.eq(text, "Hi"), s, rest, score, l)
        case WS.WSBin{data}:
          finish(s, l, score)

law srv_glued:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for c: Socket
  for l: Listener
  IO(U32)

def srv_glued(m, c, l):
  (a, r) = m
  do IO<U32>:
    u : Unit <- IO.pass(Unit, r)
    x : Unit <- Socket.close(a)
    m1 : Socket & Result<&1, &1, U32 & String, WS.WSMessage> & List<&2, U32> <- WS.recv_msg_client_framed(c, [])
    hi_got(m1, 0, l)

law srv_p2:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for c: Socket
  for l: Listener
  IO(U32)

def srv_p2(m, c, l):
  (a, r) = m
  do IO<U32>:
    u : Unit <- IO.pass(Unit, r)
    m3 : Socket & Result<&1, &1, U32 & String, Unit> <- WS.send_open_bytes((a, Done{glued()}))
    srv_glued(m3, c, l)

law srv_p1:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for c: Socket
  for l: Listener
  IO(U32)

def srv_p1(m, c, l):
  (a, r) = m
  do IO<U32>:
    u : Unit <- IO.pass(Unit, r)
    z : Unit <- IO.sleep(200)
    m2 : Socket & Result<&1, &1, U32 & String, Unit> <- WS.send_open_bytes((a, Done{hi_part2()}))
    srv_p2(m2, c, l)

law srv_start:
  for a: Socket
  for c: Socket
  for l: Listener
  IO(U32)

def srv_start(a, c, l):
  do IO<U32>:
    m1 : Socket & Result<&1, &1, U32 & String, Unit> <- WS.send_open_bytes((a, Done{hi_part1()}))
    srv_p1(m1, c, l)

law step_accept:
  for c: Socket
  for p: Listener & Result<&1, &1, U32 & String, Socket>
  IO(U32)

def step_accept(c, p):
  (l, ar) = p
  do IO<U32>:
    a : Socket <- IO.pass(Socket, ar)
    srv_start(a, c, l)

law main_go:
  for b: Listener & U32
  IO(U32)

def main_go(b):
  (l, port) = b
  do IO<U32>:
    c : Socket <- IO.try(Socket, TCP.connect("127.0.0.1", port))
    p : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
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

#|4
