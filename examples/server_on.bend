# Mirror of server.bend as a WSM.server.on handler: scripted 6-step
# ping/pong session on 127.0.0.1:19880 for examples/cliente.bend
# (or cliente_on.bend).
# Script: EvOpen(HS) -> pong s1 -> ping c1/pong -> hello/echo+ping s2 ->
# pong s2 -> close. The script is stateless: every step is identified by
# (opcode, payload), so no counter threads the handler. Prints one OK
# line per passed check and DONE 6/6 on close (grep rule: pass = DONE
# present with no FAIL); a failed check prints FAIL and closes early.
# The hello step answers echo ++ ping s2 in a single OutRaw (one WSOut
# per event). Run one server at a time (fixed port).
# Run: bend examples/server.on.bend
import Base
import ../lib/wsm.bend as WSM

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

law unwrap:
  for r: Result<&1, &1, U32 & String, List<&2, U32>>
  List<&2, U32>

def unwrap(r):
  match r:
    case Fail{e}:
      []
    case Done{bs}:
      bs

law echo_ping:
  List<&2, U32>

def echo_ping():
  List.append(&2, U32, unwrap(WSM.wsm_show_frame(True{}, 1, WSM.wsm_msg_to_bytes(WSM.WSText{"hello"}))), unwrap(WSM.wsm_show_frame(True{}, 9, [115, 50])))

law h.text:
  for ok: U32
  IO(WSM.WSOut)

def h.text(ok):
  match ok:
    case 1:
      do IO<WSM.WSOut>:
        w : Unit <- IO.print("OK TEXT")
        return WSM.OutRaw{echo_ping()}
    case _:
      do IO<WSM.WSOut>:
        w : Unit <- IO.print("FAIL TEXT")
        return WSM.wsm_out_close([])

law h.pong2:
  for s2ok: U32
  IO(WSM.WSOut)

def h.pong2(s2ok):
  match s2ok:
    case 1:
      do IO<WSM.WSOut>:
        w : Unit <- IO.print("OK PONG_S2")
        return WSM.wsm_out_close([])
    case _:
      do IO<WSM.WSOut>:
        w : Unit <- IO.print("FAIL PONG")
        return WSM.wsm_out_close([])

law h.pong1:
  for s1ok: U32
  for +pay: List<&2, U32>
  IO(WSM.WSOut)

def h.pong1(s1ok, pay):
  match s1ok:
    case 1:
      do IO<WSM.WSOut>:
        w : Unit <- IO.print("OK PONG_S1")
        return WSM.OutRaw{[]}
    case _:
      h.pong2(b2u(U32.is_eq(eq_list(pay, [115, 50]), 1)))

law h.ping:
  for ok: U32
  for +pay: List<&2, U32>
  IO(WSM.WSOut)

def h.ping(ok, pay):
  match ok:
    case 1:
      do IO<WSM.WSOut>:
        w : Unit <- IO.print("OK PING_C1")
        return WSM.wsm_out_pong(pay)
    case _:
      do IO<WSM.WSOut>:
        w : Unit <- IO.print("FAIL PING")
        return WSM.wsm_out_close([])

law h.close:
  for +pay: List<&2, U32>
  IO(WSM.WSOut)

def h.close(pay):
  do IO<WSM.WSOut>:
    w : Unit <- IO.print("OK CLOSE")
    d : Unit <- IO.print("DONE 6/6")
    return WSM.wsm_out_close(pay)

law h.err:
  for code: U32
  IO(WSM.WSOut)

def h.err(code):
  do IO<WSM.WSOut>:
    w : Unit <- IO.print("FAIL EV")
    return WSM.OutRaw{[]}

law h.serve:
  for ev: WSM.WSEv
  IO(WSM.WSOut)

def h.serve(ev):
  match ev:
    case WSM.EvOpen{}:
      do IO<WSM.WSOut>:
        w : Unit <- IO.print("OK HS")
        return WSM.wsm_out_ping([115, 49])
    case WSM.EvMsg{msg}:
      match msg:
        case WSM.WSText{text}:
          h.text(b2u(String.eq(text, "hello")))
        case WSM.WSBin{data}:
          h.text(0)
    case WSM.EvPing{pay}:
      +pp = pay
      h.ping(b2u(U32.is_eq(eq_list(pp, [99, 49]), 1)), pp)
    case WSM.EvPong{pay}:
      +pp = pay
      h.pong1(b2u(U32.is_eq(eq_list(pp, [115, 49]), 1)), pp)
    case WSM.EvClose{pay}:
      h.close(pay)
    case WSM.EvError{code, msg}:
      h.err(code)

law serve:
  for l: Listener
  IO(Unit)

def serve(l):
  do IO<Unit>:
    z : Unit <- WSM.server_on_plain(~h.serve, l)
    return z

law bound:
  for res: Result<&1, &1, U32 & String, Listener>
  IO(U32)

def bound(res):
  match res:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{l}:
      do IO<U32>:
        z : Unit <- serve(l)
        return 0

law main:
  IO(U32)

def main():
  do IO<U32>:
    res : Result<&1, &1, U32 & String, Listener> <- TCP.listen(19880)
    bound(res)
