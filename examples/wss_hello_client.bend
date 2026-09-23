# WSS coalesce probe client (task-020 phase 0, manual interop only).
# Dials the Node peer in examples/wss_hello_server.js (default port
# 19892), which sends "hello" inside its `connection` callback so the
# 101 and the first frame coalesce. Expects EvOpen then EvMsg "hello",
# prints 1 and closes. Manual only — not in check.sh (fixed port, needs
# the JS peer running): bend examples/wss_hello_client.bend
import Base
import ../lib/ws.bend as WS
import ../lib/wss.bend as WSS

law cl.text_go:
  for ok: Bool
  IO(WS.WSOut)

def cl.text_go(ok):
  match ok:
    case True{}:
      do IO<WS.WSOut>:
        w : Unit <- IO.print("1")
        return WS.OutMsg{WS.WSText{"hello"}}
    case False{}:
      do IO<WS.WSOut>:
        w : Unit <- IO.print("0")
        return WS.out_close([])

law cl.text:
  for +txt: String
  IO(WS.WSOut)

def cl.text(txt):
  cl.text_go(String.eq(txt, "hello"))

law h.cl:
  for ev: WS.WSEv
  IO(WS.WSOut)

def h.cl(ev):
  match ev:
    case WS.EvOpen{}:
      IO.pure(WS.WSOut, WS.OutRaw{[]})
    case WS.EvMsg{msg}:
      match msg:
        case WS.WSText{text}:
          cl.text(text)
        case WS.WSBin{data}:
          do IO<WS.WSOut>:
            w : Unit <- IO.print("0")
            return WS.out_close([])
    case WS.EvClose{pay}:
      IO.pure(WS.WSOut, WS.out_close([]))
    case WS.EvPing{pay}:
      IO.pure(WS.WSOut, WS.out_pong(pay))
    case WS.EvPong{pay}:
      IO.pure(WS.WSOut, WS.OutRaw{[]})
    case WS.EvError{code, msg}:
      do IO<WS.WSOut>:
        w : Unit <- IO.print("0")
        return WS.out_close([])

law main:
  IO(U32)

def main():
  do IO<U32>:
    done : Unit <- WSS.client_on_insecure(~h.cl, "127.0.0.1", 19892, "/chat", "dGhlIHNhbXBsZSBub25jZQ==")
    z : Unit <- IO.die(Unit, 0, "")
    return 0
