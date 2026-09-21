# Interop client, ON version: scripted 6-step ping/pong session against
# examples/server_on.bend (or server.js, server.bend) on
# 127.0.0.1:19880, rewritten over WS.client_on — the client is now the
# event-driven mirror of the server, not a hand-driven socket loop.
# Script: 101 -> ping s1/pong+ping c1 -> pong c1/hello -> hello/echo ->
# ping s2/pong -> close. Stateles like server_on.bend: every step is
# identified by (opcode, payload), so no counter threads the handler.
# The pong s1 step answers pong ++ ping c1 in a single OutRaw (one WSOut
# per event; a non-empty OutRaw wins over the auto-pong), mirroring the
# server's echo ++ ping s2 glue. Prints one OK line per passed check and
# DONE 6/6 on close (grep rule: pass = DONE present with no FAIL); a
# failed check prints FAIL and closes early.
# Run: bend examples/cliente_on.bend
import Base
import ../lib/ws.bend as WS

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

law pong_ping:
  List<&2, U32>

def pong_ping():
  List.append(&2, U32, unwrap(WS.client_out_bytes(WS.out_pong([115, 49]))), unwrap(WS.client_out_bytes(WS.OutOp{WS.op_ping(), [99, 49]})))

law cl.hs:
  IO(WS.WSOut)

def cl.hs():
  do IO<WS.WSOut>:
    w : Unit <- IO.print("OK HS")
    return WS.OutRaw{[]}

law cl.pong1:
  for ok: U32
  IO(WS.WSOut)

def cl.pong1(ok):
  match ok:
    case 1:
      do IO<WS.WSOut>:
        w : Unit <- IO.print("OK PONG_C1")
        return WS.OutMsg{WS.WSText{"hello"}}
    case _:
      do IO<WS.WSOut>:
        w : Unit <- IO.print("FAIL PONG")
        return WS.out_close([])

law cl.pong2:
  for ok: U32
  for +pp: List<&2, U32>
  IO(WS.WSOut)

def cl.pong2(ok, pp):
  match ok:
    case 1:
      do IO<WS.WSOut>:
        w : Unit <- IO.print("OK PONG_S2")
        return WS.out_pong(pp)
    case _:
      do IO<WS.WSOut>:
        w : Unit <- IO.print("FAIL PING")
        return WS.out_close([])

law cl.ping1:
  for s1: U32
  for s2: U32
  for +pp: List<&2, U32>
  IO(WS.WSOut)

def cl.ping1(s1, s2, pp):
  match s1:
    case 1:
      do IO<WS.WSOut>:
        w : Unit <- IO.print("OK PONG_S1")
        return WS.OutRaw{pong_ping()}
    case _:
      cl.pong2(s2, pp)

law cl.text:
  for ok: U32
  IO(WS.WSOut)

def cl.text(ok):
  match ok:
    case 1:
      do IO<WS.WSOut>:
        w : Unit <- IO.print("OK ECHO")
        return WS.OutRaw{[]}
    case _:
      do IO<WS.WSOut>:
        w : Unit <- IO.print("FAIL TEXT")
        return WS.out_close([])

law cl.close:
  for +pay: List<&2, U32>
  IO(WS.WSOut)

def cl.close(pay):
  do IO<WS.WSOut>:
    w : Unit <- IO.print("OK CLOSE")
    d : Unit <- IO.print("DONE 6/6")
    return WS.out_close(pay)

law cl.err:
  for code: U32
  IO(WS.WSOut)

def cl.err(code):
  do IO<WS.WSOut>:
    w : Unit <- IO.print("FAIL EV")
    return WS.OutRaw{[]}

law h.cl:
  for ev: WS.WSEv
  IO(WS.WSOut)

def h.cl(ev):
  match ev:
    case WS.EvOpen{}:
      cl.hs()
    case WS.EvMsg{msg}:
      match msg:
        case WS.WSText{text}:
          cl.text(b2u(String.eq(text, "hello")))
        case WS.WSBin{data}:
          cl.text(0)
    case WS.EvPing{pay}:
      +pp = pay
      cl.ping1(eq_list(pp, [115, 49]), eq_list(pp, [115, 50]), pp)
    case WS.EvPong{pay}:
      +pp = pay
      cl.pong1(eq_list(pp, [99, 49]))
    case WS.EvClose{pay}:
      +pp = pay
      cl.close(pp)
    case WS.EvError{code, msg}:
      cl.err(code)

law main:
  IO(U32)

def main():
  do IO<U32>:
    done : Unit <- WS.client_on(~h.cl, "127.0.0.1", 19880, "/chat", "dGhlIHNhbXBsZSBub25jZQ==")
    z : Unit <- IO.die(Unit, 0, "")
    return 0
