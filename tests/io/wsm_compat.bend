# io (wsm_compat): the Phase 5.7 compatibility instances of lib/wsm.bend
# over a real TCP loopback. Two connections, one per direction:
#
#   A) the raw peer plays the server: it sends ONE unmasked batch (text
#      "hi" + ping) in a single write. The test plays the client and
#      reads it with recv_bytes_plain (raw bytes), then
#      recv_msg_client_framed_plain ("hi"), then
#      recv_op_client_framed_plain (ping), then ships a sync byte with
#      send_open_bytes_plain.
#   B) the raw peer plays the client: it sends a MASKED batch (text "yo"
#      + ping) and, after the test's two sends, a masked ping alone. The
#      test plays the server with recv_msg_framed_plain ("yo"),
#      recv_op_framed_plain (ping), send_open_msg_plain,
#      send_open_op_plain and finally recv_msg_framed_plain on the lone
#      control frame, which must FAIL: recv_msg_* answers a control frame
#      as 400, never as a message (the rule the retired recv_msg_framed
#      had, owned by wsm_msg_of_frame).
#
# The masked vectors are hardcoded with key 1,2,3,4 so the readers are
# pinned against the wire, not against the builders. Golden is the sum of
# the nine checks (4 in A, 5 in B).
import Base
import ../../lib/wsm.bend as WSM
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

law canned_a:
  List<&2, U32>

def canned_a():
  [129, 2, 104, 105, 137, 2, 1, 2]

law masked_b1:
  List<&2, U32>

def masked_b1():
  [129, 130, 1, 2, 3, 4, 120, 109, 137, 130, 1, 2, 3, 4, 0, 0]

law masked_b2:
  List<&2, U32>

def masked_b2():
  [137, 130, 1, 2, 3, 4, 0, 0]

law sync_byte:
  List<&2, U32>

def sync_byte():
  [7]

law frame_ok:
  for fin: Bool
  for +op: U32
  for +pay: List<&2, U32>
  for want_op: U32
  for +want: List<&2, U32>
  Bool

def frame_ok(fin, op, pay, want_op, want):
  Bool.and(fin, Bool.and(U32.is_eq(op, want_op), U32.is_eq(eq_list(pay, want), 1)))

# Drain the peer's leftovers and hand the socket back. A Fail here is the
# expected EOF (or a reset) after the test closed its own side, so the
# socket is what matters, not the read.
law drained:
  for m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>
  Socket

def drained(m):
  (s, r) = m
  match r:
    case Fail{e}:
      s
    case Done{bs}:
      s

def peer_drain(a: Socket) -> IO(Socket):
  do IO<Socket>:
    m : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TCP.recv_bytes(a, 8192)
    return drained(m)

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

# --- scenario B (runs second: its defs come first) ----------------------

law b_done:
  for a: Socket
  for c: Socket
  for l: Listener
  for +score: U32
  IO(U32)

def b_done(a, c, l, score):
  do IO<U32>:
    x : Unit <- Socket.close(c)
    a2 : Socket <- peer_drain(a)
    y : Unit <- Socket.close(a2)
    z : Unit <- Listener.close(l)
    return score

law b_abort:
  for a: Socket
  for c: Socket
  for l: Listener
  IO(U32)

def b_abort(a, c, l):
  do IO<U32>:
    x : Unit <- Socket.close(a)
    y : Unit <- Socket.close(c)
    z : Unit <- Listener.close(l)
    return 0

law b2_got:
  for m: Socket & Result<&1, &1, U32 & String, WSM.WSMessage> & List<&2, U32>
  for a: Socket
  for l: Listener
  for +score: U32
  IO(U32)

def b2_got(m, a, l, score):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      b_done(a, s, l, (score + 1 : U32))
    case Done{msg}:
      match msg:
        case WSM.WSText{text}:
          b_done(a, s, l, score)
        case WSM.WSBin{data}:
          b_done(a, s, l, score)

law b_peer2:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for c: Socket
  for l: Listener
  for +rest: List<&2, U32>
  for +score: U32
  IO(U32)

def b_peer2(m, c, l, rest, score):
  (a, r) = m
  match r:
    case Fail{e}:
      b_abort(a, c, l)
    case Done{u}:
      do IO<U32>:
        m2 : Socket & Result<&1, &1, U32 & String, WSM.WSMessage> & List<&2, U32> <- WSM.recv_msg_framed_plain(c, rest)
        b2_got(m2, a, l, score)

law b_sent3:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for a: Socket
  for l: Listener
  for +rest: List<&2, U32>
  for +score: U32
  IO(U32)

def b_sent3(m, a, l, rest, score):
  (s, r) = m
  match r:
    case Fail{e}:
      b_abort(a, s, l)
    case Done{u}:
      do IO<U32>:
        a2 : Socket <- peer_drain(a)
        p2 : Socket & Result<&1, &1, U32 & String, Unit> <- WSM.send_open_bytes_plain((a2, Done{masked_b2()}))
        b_peer2(p2, s, l, rest, (score + 1 : U32))

law b_sent2:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for a: Socket
  for l: Listener
  for +rest: List<&2, U32>
  for +score: U32
  IO(U32)

def b_sent2(m, a, l, rest, score):
  (s, r) = m
  match r:
    case Fail{e}:
      b_abort(a, s, l)
    case Done{u}:
      do IO<U32>:
        s2 : Socket & Result<&1, &1, U32 & String, Unit> <- WSM.send_open_op_plain(s, 8, [])
        b_sent3(s2, a, l, rest, (score + 1 : U32))

law b_op_got:
  for m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>
  for a: Socket
  for l: Listener
  for +score: U32
  IO(U32)

def b_op_got(m, a, l, score):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      b_abort(a, s, l)
    case Done{t}:
      (fin, op, pay) = t
      ok = b2u(frame_ok(fin, op, pay, 9, [1, 2]))
      do IO<U32>:
        s2 : Socket & Result<&1, &1, U32 & String, Unit> <- WSM.send_open_msg_plain(s, WSM.WSText{"ok"})
        b_sent2(s2, a, l, rest, (score + ok : U32))

law b_msg_got:
  for m: Socket & Result<&1, &1, U32 & String, WSM.WSMessage> & List<&2, U32>
  for a: Socket
  for l: Listener
  for +score: U32
  IO(U32)

def b_msg_got(m, a, l, score):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      b_abort(a, s, l)
    case Done{msg}:
      match msg:
        case WSM.WSText{text}:
          ok = b2u(String.eq(text, "yo"))
          do IO<U32>:
            m2 : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- WSM.recv_op_framed_plain(s, rest)
            b_op_got(m2, a, l, (score + ok : U32))
        case WSM.WSBin{data}:
          b_abort(a, s, l)

law b_sent1:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for c: Socket
  for l: Listener
  IO(U32)

def b_sent1(m, c, l):
  (a, r) = m
  match r:
    case Fail{e}:
      b_abort(a, c, l)
    case Done{u}:
      do IO<U32>:
        m1 : Socket & Result<&1, &1, U32 & String, WSM.WSMessage> & List<&2, U32> <- WSM.recv_msg_framed_plain(c, [])
        b_msg_got(m1, a, l, 0)

law b_step:
  for c: Socket
  for p: Listener & Result<&1, &1, U32 & String, Socket>
  IO(U32)

def b_step(c, p):
  (l, ar) = p
  do IO<U32>:
    a : Socket <- IO.pass(Socket, ar)
    s1 : Socket & Result<&1, &1, U32 & String, Unit> <- WSM.send_open_bytes_plain((a, Done{masked_b1()}))
    b_sent1(s1, c, l)

law run_b:
  for b: Listener & U32
  IO(U32)

def run_b(b):
  (l, +port) = b
  do IO<U32>:
    c : Socket <- IO.try(Socket, TCP.connect("127.0.0.1", port))
    p : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    b_step(c, p)

# --- scenario A --------------------------------------------------------

law a_done:
  for a: Socket
  for c: Socket
  for l: Listener
  for +score: U32
  IO(U32)

def a_done(a, c, l, score):
  do IO<U32>:
    x : Unit <- Socket.close(c)
    a2 : Socket <- peer_drain(a)
    y : Unit <- Socket.close(a2)
    z : Unit <- Listener.close(l)
    return score

law a_abort:
  for a: Socket
  for c: Socket
  for l: Listener
  IO(U32)

def a_abort(a, c, l):
  do IO<U32>:
    x : Unit <- Socket.close(a)
    y : Unit <- Socket.close(c)
    z : Unit <- Listener.close(l)
    return 0

law a_sent2:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for a: Socket
  for l: Listener
  for +score: U32
  IO(U32)

def a_sent2(m, a, l, score):
  (s, r) = m
  match r:
    case Fail{e}:
      a_abort(a, s, l)
    case Done{u}:
      a_done(a, s, l, (score + 1 : U32))

law a_op_got:
  for m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>
  for a: Socket
  for l: Listener
  for +score: U32
  IO(U32)

def a_op_got(m, a, l, score):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      a_abort(a, s, l)
    case Done{t}:
      (fin, op, pay) = t
      ok = b2u(frame_ok(fin, op, pay, 9, [1, 2]))
      do IO<U32>:
        s2 : Socket & Result<&1, &1, U32 & String, Unit> <- WSM.send_open_bytes_plain((s, Done{sync_byte()}))
        a_sent2(s2, a, l, (score + ok : U32))

law a_msg_got:
  for m: Socket & Result<&1, &1, U32 & String, WSM.WSMessage> & List<&2, U32>
  for a: Socket
  for l: Listener
  for +score: U32
  IO(U32)

def a_msg_got(m, a, l, score):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      a_abort(a, s, l)
    case Done{msg}:
      match msg:
        case WSM.WSText{text}:
          ok = b2u(String.eq(text, "hi"))
          do IO<U32>:
            m2 : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- WSM.recv_op_client_framed_plain(s, rest)
            a_op_got(m2, a, l, (score + ok : U32))
        case WSM.WSBin{data}:
          a_abort(a, s, l)

law a_raw_got:
  for m: Socket & Result<&1, &1, U32 & String, List<&2, U32>>
  for a: Socket
  for l: Listener
  IO(U32)

def a_raw_got(m, a, l):
  (s, r) = m
  match r:
    case Fail{e}:
      a_abort(a, s, l)
    case Done{+bs}:
      ok = eq_list(bs, canned_a())
      do IO<U32>:
        m2 : Socket & Result<&1, &1, U32 & String, WSM.WSMessage> & List<&2, U32> <- WSM.recv_msg_client_framed_plain(s, bs)
        a_msg_got(m2, a, l, ok)

law a_sent1:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for c: Socket
  for l: Listener
  IO(U32)

def a_sent1(m, c, l):
  (a, r) = m
  match r:
    case Fail{e}:
      a_abort(a, c, l)
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- WSM.recv_bytes_plain(c)
        a_raw_got(got, a, l)

law a_step:
  for c: Socket
  for p: Listener & Result<&1, &1, U32 & String, Socket>
  IO(U32)

def a_step(c, p):
  (l, ar) = p
  do IO<U32>:
    a : Socket <- IO.pass(Socket, ar)
    s1 : Socket & Result<&1, &1, U32 & String, Unit> <- WSM.send_open_bytes_plain((a, Done{canned_a()}))
    a_sent1(s1, c, l)

law run_a:
  for b: Listener & U32
  IO(U32)

def run_a(b):
  (l, +port) = b
  do IO<U32>:
    c : Socket <- IO.try(Socket, TCP.connect("127.0.0.1", port))
    p : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    a_step(c, p)

law main:
  IO(U32)

def main():
  do IO<U32>:
    ba : Listener & U32 <- listen_any(32n, 19710)
    +sa : U32 <- run_a(ba)
    bb : Listener & U32 <- listen_any(32n, 19711)
    +sb : U32 <- run_b(bb)
    +total : U32 = (sa + sb : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

#|9
