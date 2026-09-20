# lib (ws_server_on): WS.server_on — the generic persistent server.
# Pure: opcode consts, out_* builders, ping_reply/close_answer policy
# (explicit OutOp wins, non-empty OutRaw wins too — it may glue the pong
# with the next frame; OutRaw{[]} and OutMsg fall back to the auto-pong).
# Net: one server_on echo handler serves text, ping, a second text and
# close on the SAME connection (persistence proof); the client speaks
# masked frames and reads unmasked replies with buf threaded step by
# step. Scores pure*10000 + echo1*1000 + pong*100 + echo2*10 + close.
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

law is_outop:
  for w: WS.WSOut
  for want_op: U32
  for +want: List<&2, U32>
  U32

def is_outop(w, want_op, want):
  match w:
    case WS.OutMsg{msg}:
      0
    case WS.OutOp{op, pay}:
      b2u(Bool.and(U32.is_eq(op, want_op), U32.is_eq(eq_list(pay, want), 1)))
    case WS.OutRaw{bs}:
      0

law is_outraw:
  for w: WS.WSOut
  for +want: List<&2, U32>
  U32

def is_outraw(w, want):
  match w:
    case WS.OutRaw{bs}:
      b2u(U32.is_eq(eq_list(bs, want), 1))
    case _:
      0

law chk_ops:
  U32

def chk_ops():
  b2u(U32.is_eq((b2u(U32.is_eq(WS.op_text(), 1)) + b2u(U32.is_eq(WS.op_bin(), 2)) + b2u(U32.is_eq(WS.op_close(), 8)) + b2u(U32.is_eq(WS.op_ping(), 9)) + b2u(U32.is_eq(WS.op_pong(), 10)) : U32), 5))

law chk_build:
  U32

def chk_build():
  (is_outop(WS.out_pong([7]), 10, [7]) * is_outop(WS.out_close([5]), 8, [5]) : U32)

law chk_ping:
  U32

def chk_ping():
  (is_outop(WS.ping_reply([1], WS.OutOp{5, [2]}), 5, [2]) * is_outop(WS.ping_reply([1], WS.OutMsg{WS.WSText{"x"}}), 10, [1]) * is_outop(WS.ping_reply([1], WS.OutRaw{[]}), 10, [1]) * is_outraw(WS.ping_reply([1], WS.OutRaw{[9]}), [9]) : U32)

law chk_close:
  U32

def chk_close():
  (is_outop(WS.close_answer([1], WS.OutOp{5, [2]}), 5, [2]) * is_outop(WS.close_answer([1], WS.OutMsg{WS.WSText{"x"}}), 8, [1]) : U32)

law pure:
  U32

def pure():
  b2u(U32.is_eq((chk_ops() + chk_build() + chk_ping() + chk_close() : U32), 4))

law h.handle:
  for ev: WS.WSEv
  IO(WS.WSOut)

def h.handle(ev):
  match ev:
    case WS.EvOpen{}:
      IO.pure(WS.WSOut, WS.OutRaw{[]})
    case WS.EvMsg{msg}:
      match msg:
        case WS.WSText{text}:
          IO.pure(WS.WSOut, WS.OutMsg{WS.WSText{text}})
        case WS.WSBin{data}:
          IO.pure(WS.WSOut, WS.OutMsg{WS.WSBin{data}})
    case WS.EvPing{pay}:
      IO.pure(WS.WSOut, WS.out_pong(pay))
    case WS.EvPong{pay}:
      IO.pure(WS.WSOut, WS.OutRaw{[]})
    case WS.EvClose{pay}:
      IO.pure(WS.WSOut, WS.out_close(pay))
    case WS.EvError{code, msg}:
      IO.pure(WS.WSOut, WS.OutRaw{[]})

law server_side:
  for l: Listener
  IO(Unit)

def server_side(l):
  do IO<Unit>:
    z : Unit <- WS.server_on(~h.handle, l)
    return z

law cli.dead:
  for s: Socket
  for +acc: U32
  IO(U32)

def cli.dead(s, acc):
  do IO<U32>:
    x : Unit <- Socket.close(s)
    +total : U32 = acc
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law cli.clgot:
  for m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>
  for +acc: U32
  IO(U32)

def cli.clgot(m, acc):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      cli.dead(s, acc)
    case Done{t}:
      (fin, op, pay) = t
      cli.dead(s, (acc + b2u(U32.is_eq(op, 8)) : U32))

law cli.clsent:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for buf: List<&2, U32>
  for +acc: U32
  IO(U32)

def cli.clsent(m, buf, acc):
  (s, r) = m
  match r:
    case Fail{e}:
      cli.dead(s, acc)
    case Done{u}:
      do IO<U32>:
        m2 : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- WS.recv_op_client_framed(s, buf)
        cli.clgot(m2, acc)

law cli.t2got:
  for m: Socket & Result<&1, &1, U32 & String, WS.WSMessage> & List<&2, U32>
  for +acc: U32
  IO(U32)

def cli.t2got(m, acc):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      cli.dead(s, acc)
    case Done{msg}:
      match msg:
        case WS.WSText{text}:
          ok = b2u(String.eq(text, "yo"))
          do IO<U32>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- WS.client_send_op(s, 8, [])
            cli.clsent(sent, rest, (acc + ok * 10 : U32))
        case WS.WSBin{data}:
          cli.dead(s, acc)

law cli.t2sent:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for buf: List<&2, U32>
  for +acc: U32
  IO(U32)

def cli.t2sent(m, buf, acc):
  (s, r) = m
  match r:
    case Fail{e}:
      cli.dead(s, acc)
    case Done{u}:
      do IO<U32>:
        m2 : Socket & Result<&1, &1, U32 & String, WS.WSMessage> & List<&2, U32> <- WS.recv_msg_client_framed(s, buf)
        cli.t2got(m2, acc)

law cli.pggot:
  for m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>
  for +acc: U32
  IO(U32)

def cli.pggot(m, acc):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      cli.dead(s, acc)
    case Done{t}:
      (fin, op, pay) = t
      ok = b2u(Bool.and(U32.is_eq(op, 10), U32.is_eq(eq_list(pay, [1, 2]), 1)))
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- WS.client_send_msg(s, WS.WSText{"yo"})
        cli.t2sent(sent, rest, (acc + ok * 100 : U32))

law cli.pgsent:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for buf: List<&2, U32>
  for +acc: U32
  IO(U32)

def cli.pgsent(m, buf, acc):
  (s, r) = m
  match r:
    case Fail{e}:
      cli.dead(s, acc)
    case Done{u}:
      do IO<U32>:
        m2 : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- WS.recv_op_client_framed(s, buf)
        cli.pggot(m2, acc)

law cli.t1got:
  for m: Socket & Result<&1, &1, U32 & String, WS.WSMessage> & List<&2, U32>
  for +acc: U32
  IO(U32)

def cli.t1got(m, acc):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      cli.dead(s, acc)
    case Done{msg}:
      match msg:
        case WS.WSText{text}:
          ok = b2u(String.eq(text, "hi"))
          do IO<U32>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- WS.client_send_op(s, 9, [1, 2])
            cli.pgsent(sent, rest, (acc + ok * 1000 : U32))
        case WS.WSBin{data}:
          cli.dead(s, acc)

law cli.t1sent:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for +acc: U32
  IO(U32)

def cli.t1sent(m, acc):
  (s, r) = m
  match r:
    case Fail{e}:
      cli.dead(s, acc)
    case Done{u}:
      do IO<U32>:
        m2 : Socket & Result<&1, &1, U32 & String, WS.WSMessage> & List<&2, U32> <- WS.recv_msg_client_framed(s, [])
        cli.t1got(m2, acc)

law cli.session:
  for ok: U32
  for s: Socket
  for +acc: U32
  IO(U32)

def cli.session(ok, s, acc):
  match ok:
    case 1:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- WS.client_send_msg(s, WS.WSText{"hi"})
        cli.t1sent(sent, acc)
    case _:
      cli.dead(s, acc)

law cli.hs1:
  for m: Socket & Result<&1, &1, U32 & String, String>
  for +acc: U32
  IO(U32)

def cli.hs1(m, acc):
  (s, r) = m
  match r:
    case Fail{e}:
      cli.dead(s, acc)
    case Done{resp}:
      cli.session(b2u(String.contains(resp, "101")), s, acc)

law cli.sent1:
  for m: Socket & Result<&1, &1, U32 & String, Unit>
  for +acc: U32
  IO(U32)

def cli.sent1(m, acc):
  (s, r) = m
  match r:
    case Fail{e}:
      cli.dead(s, acc)
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 8192)
        cli.hs1(got, acc)

law cli.open:
  for conn: Result<&1, &1, U32 & String, Socket>
  for +req_txt: String
  for +acc: U32
  IO(U32)

def cli.open(conn, req_txt, acc):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        m : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req_txt)
        cli.sent1(m, acc)

law cli.start:
  for +host: String
  for port: U32
  for req: Result<&1, &1, U32 & String, String>
  for +acc: U32
  IO(U32)

def cli.start(host, port, req, acc):
  match req:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{req_txt}:
      do IO<U32>:
        conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect(host, port)
        cli.open(conn, req_txt, acc)

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
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l))
    cli.start("127.0.0.1", port, WS.client_request("127.0.0.1", "/chat", "dGhlIHNhbXBsZSBub25jZQ=="), (pure() * 10000 : U32))

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 19690)
    main_go(b)

#|11111
