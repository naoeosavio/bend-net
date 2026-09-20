# lib (ws_client_on): WS.client_on — the generic persistent client.
# Mirror of ws_server_on.bend: the same scripted session, driven by the
# client_on handler instead of the wire. One server_on handler serves
# the whole script on ONE connection (echo "hi", close on "yo"); the
# client handler checks each event it receives and prints one digit per
# step: open -> send "hi", echo -> send ping [1,2], pong -> send "yo",
# echo -> silent, server close -> reply close. A wrong payload prints 0
# and aborts the session with a close.
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

# Server side: echo "hi", close on "yo" (the server initiates the
# close, the client replies through its EvClose branch).

law srv.msg2:
  for is_hi: Bool
  IO(WS.WSOut)

def srv.msg2(is_hi):
  match is_hi:
    case True{}:
      IO.pure(WS.WSOut, WS.OutMsg{WS.WSText{"hi"}})
    case False{}:
      IO.pure(WS.WSOut, WS.out_close([]))

law h.srv:
  for ev: WS.WSEv
  IO(WS.WSOut)

def h.srv(ev):
  match ev:
    case WS.EvOpen{}:
      IO.pure(WS.WSOut, WS.OutRaw{[]})
    case WS.EvMsg{msg}:
      match msg:
        case WS.WSText{text}:
          +txt = text
          srv.msg2(String.eq(txt, "hi"))
        case WS.WSBin{data}:
          IO.pure(WS.WSOut, WS.out_close([]))
    case WS.EvPing{pay}:
      IO.pure(WS.WSOut, WS.out_pong(pay))
    case WS.EvPong{pay}:
      IO.pure(WS.WSOut, WS.OutRaw{[]})
    case WS.EvClose{pay}:
      IO.pure(WS.WSOut, WS.out_close(pay))
    case WS.EvError{code, msg}:
      IO.pure(WS.WSOut, WS.OutRaw{[]})

# Client side: every step prints its digit, checks ride the payload.

law cl.step:
  for ok: Bool
  for out: WS.WSOut
  IO(WS.WSOut)

def cl.step(ok, out):
  do IO<WS.WSOut>:
    w : Unit <- IO.print(Bool.pick(String, ok, "1", "0"))
    return out

law cl.msg3:
  for is_yo: Bool
  IO(WS.WSOut)

def cl.msg3(is_yo):
  match is_yo:
    case True{}:
      cl.step(True{}, WS.OutRaw{[]})
    case False{}:
      cl.step(False{}, WS.out_close([]))

law cl.msg2:
  for is_hi: Bool
  for is_yo: Bool
  IO(WS.WSOut)

def cl.msg2(is_hi, is_yo):
  match is_hi:
    case True{}:
      cl.step(True{}, WS.OutOp{WS.op_ping(), [1, 2]})
    case False{}:
      cl.msg3(is_yo)

law cl.pong:
  for +pay: List<&2, U32>
  IO(WS.WSOut)

def cl.pong(pay):
  +ok = U32.is_eq(eq_list(pay, [1, 2]), 1)
  cl.step(ok, WS.OutMsg{WS.WSText{"yo"}})

law h.cl:
  for ev: WS.WSEv
  IO(WS.WSOut)

def h.cl(ev):
  match ev:
    case WS.EvOpen{}:
      cl.step(True{}, WS.OutMsg{WS.WSText{"hi"}})
    case WS.EvMsg{msg}:
      match msg:
        case WS.WSText{text}:
          +txt = text
          cl.msg2(String.eq(txt, "hi"), String.eq(txt, "yo"))
        case WS.WSBin{data}:
          cl.step(False{}, WS.out_close([]))
    case WS.EvPong{pay}:
      cl.pong(pay)
    case WS.EvClose{pay}:
      cl.step(True{}, WS.out_close([]))
    case WS.EvPing{pay}:
      cl.step(False{}, WS.out_close([]))
    case WS.EvError{code, msg}:
      cl.step(False{}, WS.out_close([]))

law server_side:
  for l: Listener
  IO(Unit)

def server_side(l):
  do IO<Unit>:
    z : Unit <- WS.server_on(~h.srv, l)
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
    done : Unit <- WS.client_on(~h.cl, "127.0.0.1", port, "/chat", "dGhlIHNhbXBsZSBub25jZQ==")
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
