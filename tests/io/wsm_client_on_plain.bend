# lib (wsm_client_on_plain): WSM.client_on_plain — the generic persistent client.
# Mirror of wsm_server_on_plain.bend: the same scripted session, driven by the
# client_on handler instead of the wire. One server_on handler serves
# the whole script on ONE connection (echo "hi", close on "yo"); the
# client handler checks each event it receives and prints one digit per
# step: open -> send "hi", echo -> send ping [1,2], pong -> send "yo",
# echo -> silent, server close -> reply close. A wrong payload prints 0
# and aborts the session with a close.
import Base
import ../../lib/wsm.bend as WSM

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

# Server side: echo "hi", close on "yo" (the server initiates the
# close, the client replies through its EvClose branch).

law srv.msg2:
  for is_hi: Bool
  IO(WSM.WSOut)

def srv.msg2(is_hi):
  match is_hi:
    case True{}:
      IO.pure(WSM.WSOut, WSM.OutMsg{WSM.WSText{"hi"}})
    case False{}:
      IO.pure(WSM.WSOut, WSM.wsm_out_close([]))

law h.srv:
  for ev: WSM.WSEv
  IO(WSM.WSOut)

def h.srv(ev):
  match ev:
    case WSM.EvOpen{}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})
    case WSM.EvMsg{msg}:
      match msg:
        case WSM.WSText{text}:
          +txt = text
          srv.msg2(String.eq(txt, "hi"))
        case WSM.WSBin{data}:
          IO.pure(WSM.WSOut, WSM.wsm_out_close([]))
    case WSM.EvPing{pay}:
      IO.pure(WSM.WSOut, WSM.wsm_out_pong(pay))
    case WSM.EvPong{pay}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})
    case WSM.EvClose{pay}:
      IO.pure(WSM.WSOut, WSM.wsm_out_close(pay))
    case WSM.EvError{code, msg}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})

# Client side: every step prints its digit, checks ride the payload.

law cl.step:
  for ok: Bool
  for out: WSM.WSOut
  IO(WSM.WSOut)

def cl.step(ok, out):
  do IO<WSM.WSOut>:
    w : Unit <- IO.print(Bool.pick(String, ok, "1", "0"))
    return out

law cl.msg3:
  for is_yo: Bool
  IO(WSM.WSOut)

def cl.msg3(is_yo):
  match is_yo:
    case True{}:
      cl.step(True{}, WSM.OutRaw{[]})
    case False{}:
      cl.step(False{}, WSM.wsm_out_close([]))

law cl.msg2:
  for is_hi: Bool
  for is_yo: Bool
  IO(WSM.WSOut)

def cl.msg2(is_hi, is_yo):
  match is_hi:
    case True{}:
      cl.step(True{}, WSM.OutOp{WSM.wsm_op_ping(), [1, 2]})
    case False{}:
      cl.msg3(is_yo)

law cl.pong:
  for +pay: List<&2, U32>
  IO(WSM.WSOut)

def cl.pong(pay):
  +ok = U32.is_eq(eq_list(pay, [1, 2]), 1)
  cl.step(ok, WSM.OutMsg{WSM.WSText{"yo"}})

law h.cl:
  for ev: WSM.WSEv
  IO(WSM.WSOut)

def h.cl(ev):
  match ev:
    case WSM.EvOpen{}:
      cl.step(True{}, WSM.OutMsg{WSM.WSText{"hi"}})
    case WSM.EvMsg{msg}:
      match msg:
        case WSM.WSText{text}:
          +txt = text
          cl.msg2(String.eq(txt, "hi"), String.eq(txt, "yo"))
        case WSM.WSBin{data}:
          cl.step(False{}, WSM.wsm_out_close([]))
    case WSM.EvPong{pay}:
      cl.pong(pay)
    case WSM.EvClose{pay}:
      cl.step(True{}, WSM.wsm_out_close([]))
    case WSM.EvPing{pay}:
      cl.step(False{}, WSM.wsm_out_close([]))
    case WSM.EvError{code, msg}:
      cl.step(False{}, WSM.wsm_out_close([]))

law server_side:
  for l: Listener
  IO(Unit)

def server_side(l):
  do IO<Unit>:
    z : Unit <- WSM.server_on_plain(~h.srv, l)
    return z

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
    done : Unit <- WSM.client_on_plain(~h.cl, "127.0.0.1", port, "/chat", "dGhlIHNhbXBsZSBub25jZQ==")
    z : Unit <- IO.die(Unit, 0, "")
    return 0

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 19790)
    main_go(b)

#|1
#|1
#|1
#|1
