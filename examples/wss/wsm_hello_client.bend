# WSS coalesce probe client (task-020 phase 0, manual interop only).
# Dials the Node peer in examples/wss/wss_hello_server.js (default port
# 19892), which sends "hello" inside its `connection` callback so the
# 101 and the first frame coalesce. Expects EvOpen then EvMsg "hello",
# prints 1 and closes. Manual only — not in check.sh (fixed port, needs
# the JS peer running): bend examples/wss/wsm_hello_client.bend
import Base
import ../../lib/wsm.bend as WSM

law cl.text_go:
  for ok: Bool
  IO(WSM.WSOut)

def cl.text_go(ok):
  match ok:
    case True{}:
      do IO<WSM.WSOut>:
        w : Unit <- IO.print("1")
        return WSM.OutMsg{WSM.WSText{"hello"}}
    case False{}:
      do IO<WSM.WSOut>:
        w : Unit <- IO.print("0")
        return WSM.wsm_out_close([])

law cl.text:
  for +txt: String
  IO(WSM.WSOut)

def cl.text(txt):
  cl.text_go(String.eq(txt, "hello"))

law h.cl:
  for ev: WSM.WSEv
  IO(WSM.WSOut)

def h.cl(ev):
  match ev:
    case WSM.EvOpen{}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})
    case WSM.EvMsg{msg}:
      match msg:
        case WSM.WSText{text}:
          cl.text(text)
        case WSM.WSBin{data}:
          do IO<WSM.WSOut>:
            w : Unit <- IO.print("0")
            return WSM.wsm_out_close([])
    case WSM.EvClose{pay}:
      IO.pure(WSM.WSOut, WSM.wsm_out_close([]))
    case WSM.EvPing{pay}:
      IO.pure(WSM.WSOut, WSM.wsm_out_pong(pay))
    case WSM.EvPong{pay}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})
    case WSM.EvError{code, msg}:
      do IO<WSM.WSOut>:
        w : Unit <- IO.print("0")
        return WSM.wsm_out_close([])

law main:
  IO(U32)

def main():
  do IO<U32>:
    done : Unit <- WSM.client_on_insecure(~h.cl, "127.0.0.1", 19892, "/chat", "dGhlIHNhbXBsZSBub25jZQ==")
    z : Unit <- IO.die(Unit, 0, "")
    return 0
