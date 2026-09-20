# Mirror of server.js in Bend: scripted 6-step ping/pong session on
# 127.0.0.1:19880 for lib/exemplos/cliente.bend.
# Script: 101 -> ping s1/pong -> ping c1/pong -> hello/echo ->
# ping s2/pong -> close. Prints the score (6 when all passes).
# Run one server at a time (fixed port).
# Run: bun bend2/main.ts lib/exemplos/server.bend
import Base
import ../ws.bend as WS

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

law close_checked:
  for ok: Bool
  for s: Socket
  for score: U32
  IO(U32)

def close_checked(ok, s, score):
  match ok:
    case True{}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return (score + 1 : U32)
    case False{}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score

law close_got:
  for m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>
  for score: U32
  IO(U32)

def close_got(m, score):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score
    case Done{t}:
      (fin, op, pay) = t
      close_checked(U32.is_eq(op, 8), s, score)

law close_sent:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for score: U32
  IO(U32)

def close_sent(m, score):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score
    case Done{u}:
      do IO<U32>:
        m2 : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> <- WS.recv_op(s)
        close_got(m2, score)

law pong2_checked:
  for ok: Bool
  for s: Socket
  for score: U32
  IO(U32)

def pong2_checked(ok, s, score):
  match ok:
    case True{}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- WS.send_open_op(s, 8, [])
        close_sent(sent, (score + 1 : U32))
    case False{}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score

law pong_s2_got:
  for m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>
  for score: U32
  IO(U32)

def pong_s2_got(m, score):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score
    case Done{t}:
      (fin, op, pay) = t
      pong2_checked(expect_frame(fin, op, pay, 10, [115, 50]), s, score)

law ping_s2_sent:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for score: U32
  IO(U32)

def ping_s2_sent(m, score):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score
    case Done{u}:
      do IO<U32>:
        m2 : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> <- WS.recv_op(s)
        pong_s2_got(m2, score)

law echo_done:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for score: U32
  IO(U32)

def echo_done(m, score):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score
    case Done{u}:
      do IO<U32>:
        z : Unit <- IO.sleep(100)
        p : Socket & Result<&1, &1, U32 & String, Unit> <- WS.send_open_op(s, 9, [115, 50])
        ping_s2_sent(p, score)

law text_checked:
  for ok: Bool
  for s: Socket
  for score: U32
  IO(U32)

def text_checked(ok, s, score):
  match ok:
    case True{}:
      do IO<U32>:
        e1 : Socket & Result<&1, &1, U32 & String, Unit> <- WS.send_open_msg(s, WS.WSText{"hello"})
        echo_done(e1, (score + 1 : U32))
    case False{}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score

law text_got:
  for m: Socket & Result<&1, &1, U32 & String, WS.WSMessage>
  for score: U32
  IO(U32)

def text_got(m, score):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score
    case Done{msg}:
      match msg:
        case WS.WSText{text}:
          text_checked(String.eq(text, "hello"), s, score)
        case WS.WSBin{data}:
          do IO<U32>:
            x : Unit <- Socket.close(s)
            return score

law pong_c1_sent:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for score: U32
  IO(U32)

def pong_c1_sent(m, score):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score
    case Done{u}:
      do IO<U32>:
        m2 : Socket & Result<&1, &1, U32 & String, WS.WSMessage> <- WS.recv_msg(s)
        text_got(m2, score)

law ping_c1_checked:
  for ok: Bool
  for s: Socket
  for score: U32
  IO(U32)

def ping_c1_checked(ok, s, score):
  match ok:
    case True{}:
      do IO<U32>:
        p : Socket & Result<&1, &1, U32 & String, Unit> <- WS.send_open_op(s, 10, [99, 49])
        pong_c1_sent(p, (score + 1 : U32))
    case False{}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score

law ping_c1_got:
  for m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>
  for score: U32
  IO(U32)

def ping_c1_got(m, score):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score
    case Done{t}:
      (fin, op, pay) = t
      ping_c1_checked(expect_frame(fin, op, pay, 9, [99, 49]), s, score)

law pong_s1_checked:
  for ok: Bool
  for s: Socket
  for score: U32
  IO(U32)

def pong_s1_checked(ok, s, score):
  match ok:
    case True{}:
      do IO<U32>:
        m2 : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> <- WS.recv_op(s)
        ping_c1_got(m2, (score + 1 : U32))
    case False{}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score

law pong_s1_got:
  for m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>
  for score: U32
  IO(U32)

def pong_s1_got(m, score):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score
    case Done{t}:
      (fin, op, pay) = t
      pong_s1_checked(expect_frame(fin, op, pay, 10, [115, 49]), s, score)

law ping_s1_sent:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for score: U32
  IO(U32)

def ping_s1_sent(m, score):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score
    case Done{u}:
      do IO<U32>:
        m2 : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> <- WS.recv_op(s)
        pong_s1_got(m2, score)

law reply_sent:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for score: U32
  IO(U32)

def reply_sent(m, score):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score
    case Done{u}:
      do IO<U32>:
        z : Unit <- IO.sleep(100)
        p : Socket & Result<&1, &1, U32 & String, Unit> <- WS.send_open_op(s, 9, [115, 49])
        ping_s1_sent(p, score)

law reply_101:
  for hres: Result<&1, &1, U32 & String, String>
  for s: Socket
  IO(U32)

def reply_101(hres, s):
  match hres:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return 0
    case Done{resp}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(s, resp)
        reply_sent(sent, 1)

law hs_got:
  for m: Socket & Result<&1, &1, U32 & String, String>
  IO(U32)

def hs_got(m):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return 0
    case Done{req}:
      reply_101(WS.handshake(req), s)

law accepted:
  for m1: Listener & Result<&1, &1, U32 & String, Socket>
  IO(U32)

def accepted(m1):
  (l, r) = m1
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Listener.close(l)
        return 0
    case Done{sock}:
      do IO<U32>:
        x : Unit <- Listener.close(l)
        got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(sock, 8192)
        hs_got(got)

law serve:
  for l: Listener
  IO(U32)

def serve(l):
  do IO<U32>:
    m1 : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    accepted(m1)

law bound:
  for res: Result<&1, &1, U32 & String, Listener>
  IO(U32)

def bound(res):
  match res:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{l}:
      serve(l)

law main:
  IO(U32)

def main():
  do IO<U32>:
    res : Result<&1, &1, U32 & String, Listener> <- TCP.listen(19880)
    +total : U32 <- bound(res)
    w : Unit <- IO.print(U32.show(total))
    return total
