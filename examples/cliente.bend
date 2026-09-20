# Interop client: scripted 6-step ping/pong session against
# lib/exemplos/server.js (or server.bend) on 127.0.0.1:19880.
# Script: 101 -> ping s1/pong -> ping c1/pong -> hello/echo ->
# ping s2/pong -> close. Prints the score (6 when all passes).
# Run: bun bend2/main.ts lib/exemplos/cliente.bend
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

law close_shipped:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for score: U32
  IO(U32)

def close_shipped(m, score):
  (s, r) = m
  do IO<U32>:
    x : Unit <- Socket.close(s)
    return score

law close_checked:
  for ok: Bool
  for s: Socket
  for score: U32
  IO(U32)

def close_checked(ok, s, score):
  match ok:
    case True{}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- WS.client_send_op(s, 8, [])
        close_shipped(sent, (score + 1 : U32))
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

law wait_close:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for score: U32
  IO(U32)

def wait_close(m, score):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score
    case Done{u}:
      do IO<U32>:
        m2 : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> <- WS.recv_op_client(s)
        close_got(m2, score)

law pong2_go:
  for ok: Bool
  for s: Socket
  for pay: List<&2, U32>
  for score: U32
  IO(U32)

def pong2_go(ok, s, pay, score):
  match ok:
    case True{}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- WS.client_send_op(s, 10, pay)
        wait_close(sent, (score + 1 : U32))
    case False{}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score

law pong2_next:
  for fin: Bool
  for +op: U32
  for +pay: List<&2, U32>
  for s: Socket
  for score: U32
  IO(U32)

def pong2_next(fin, op, pay, s, score):
  pong2_go(expect_frame(fin, op, pay, 9, [115, 50]), s, pay, score)

law ping2_got:
  for m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>
  for score: U32
  IO(U32)

def ping2_got(m, score):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score
    case Done{t}:
      (fin, op, pay) = t
      pong2_next(fin, op, pay, s, score)

law echo_checked:
  for ok: Bool
  for s: Socket
  for score: U32
  IO(U32)

def echo_checked(ok, s, score):
  match ok:
    case True{}:
      do IO<U32>:
        m2 : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> <- WS.recv_op_client(s)
        ping2_got(m2, (score + 1 : U32))
    case False{}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score

law echo_got:
  for m: Socket & Result<&1, &1, U32 & String, WS.WSMessage>
  for score: U32
  IO(U32)

def echo_got(m, score):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score
    case Done{msg}:
      match msg:
        case WS.WSText{text}:
          echo_checked(String.eq(text, "hello"), s, score)
        case WS.WSBin{data}:
          do IO<U32>:
            x : Unit <- Socket.close(s)
            return score

law hello_sent:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for score: U32
  IO(U32)

def hello_sent(m, score):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score
    case Done{u}:
      do IO<U32>:
        m2 : Socket & Result<&1, &1, U32 & String, WS.WSMessage> <- WS.recv_msg_client(s)
        echo_got(m2, score)

law hello_next:
  for ok: Bool
  for s: Socket
  for score: U32
  IO(U32)

def hello_next(ok, s, score):
  match ok:
    case True{}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- WS.client_send_msg(s, WS.WSText{"hello"})
        hello_sent(sent, (score + 1 : U32))
    case False{}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score

law pong1_got:
  for m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>
  for score: U32
  IO(U32)

def pong1_got(m, score):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score
    case Done{t}:
      (fin, op, pay) = t
      hello_next(expect_frame(fin, op, pay, 10, [99, 49]), s, score)

law ping_c1_sent:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for score: U32
  IO(U32)

def ping_c1_sent(m, score):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score
    case Done{u}:
      do IO<U32>:
        m2 : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> <- WS.recv_op_client(s)
        pong1_got(m2, score)

law pong_s1_sent:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for score: U32
  IO(U32)

def pong_s1_sent(m, score):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score
    case Done{u}:
      do IO<U32>:
        sent2 : Socket & Result<&1, &1, U32 & String, Unit> <- WS.client_send_op(s, 9, [99, 49])
        ping_c1_sent(sent2, score)

law s1_go:
  for ok: Bool
  for s: Socket
  for pay: List<&2, U32>
  for score: U32
  IO(U32)

def s1_go(ok, s, pay, score):
  match ok:
    case True{}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- WS.client_send_op(s, 10, pay)
        pong_s1_sent(sent, (score + 1 : U32))
    case False{}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score

law s1_next:
  for fin: Bool
  for +op: U32
  for +pay: List<&2, U32>
  for s: Socket
  for score: U32
  IO(U32)

def s1_next(fin, op, pay, s, score):
  s1_go(expect_frame(fin, op, pay, 9, [115, 49]), s, pay, score)

law ping_s1_got:
  for m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>>
  for score: U32
  IO(U32)

def ping_s1_got(m, score):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return score
    case Done{t}:
      (fin, op, pay) = t
      s1_next(fin, op, pay, s, score)

law session:
  for ok: Bool
  for s: Socket
  IO(U32)

def session(ok, s):
  match ok:
    case True{}:
      do IO<U32>:
        m : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> <- WS.recv_op_client(s)
        ping_s1_got(m, 1)
    case False{}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return 0

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
    case Done{resp}:
      session(String.contains(resp, "101"), s)

law req_sent:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  IO(U32)

def req_sent(m):
  (s, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        return 0
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 8192)
        hs_got(got)

law conn_open:
  for conn: Result<&1, &1, U32 & String, Socket>
  for +req_txt: String
  IO(U32)

def conn_open(conn, req_txt):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req_txt)
        req_sent(sent)

law start_req:
  for +host: String
  for port: U32
  for req: Result<&1, &1, U32 & String, String>
  IO(U32)

def start_req(host, port, req):
  match req:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{req_txt}:
      do IO<U32>:
        conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect(host, port)
        conn_open(conn, req_txt)

law start:
  for +host: String
  for port: U32
  for +key: String
  IO(U32)

def start(host, port, key):
  start_req(host, port, WS.client_request(host, "/chat", key))

law main:
  IO(U32)

def main():
  do IO<U32>:
    +total : U32 <- start("127.0.0.1", 19880, "dGhlIHNhbXBsZSBub25jZQ==")
    w : Unit <- IO.print(U32.show(total))
    return total
