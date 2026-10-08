# WSS fragment echo client (task-020 phase 1, manual interop only).
# Sends one 32000-byte binary message to a Node `ws` echo peer on
# 127.0.0.1:19894 and prints 1 when the full echo lands (0 otherwise).
# The payload rides two 16KB chunks: `bend run` faults past ~25KB on a
# single replicate-built list, so run this through a built binary:
# bend examples/wss/wsm_frag_client.bend -o /tmp/frag_client_bin &&
#   /tmp/frag_client_bin
# Manual only — not in check.sh.
import Base
import ../../lib/wsm.bend as WSM

law big_msg:
  List<&2, U32>

def big_msg():
  List.append(&2, U32, List.replicate(U32, 16000n, 97), List.replicate(U32, 16000n, 98))

law cl.msg.go:
  for +data: List<&2, U32>
  for ok: Bool
  IO(WSM.WSOut)

def cl.msg.go(data, ok):
  match ok:
    case True{}:
      do IO<WSM.WSOut>:
        w : Unit <- IO.print("1")
        return WSM.wsm_out_close([])
    case False{}:
      do IO<WSM.WSOut>:
        w : Unit <- IO.print("0")
        return WSM.wsm_out_close([])

law cl.msg:
  for +data: List<&2, U32>
  IO(WSM.WSOut)

def cl.msg(data):
  cl.msg.go(data, U32.is_eq(U32.from_nat(List.length(&2, U32, data)), 32000))

law h.cl:
  for ev: WSM.WSEv
  IO(WSM.WSOut)

def h.cl(ev):
  match ev:
    case WSM.EvOpen{}:
      IO.pure(WSM.WSOut, WSM.OutMsg{WSM.WSBin{big_msg()}})
    case WSM.EvMsg{msg}:
      match msg:
        case WSM.WSText{text}:
          do IO<WSM.WSOut>:
            w : Unit <- IO.print("0")
            return WSM.wsm_out_close([])
        case WSM.WSBin{data}:
          cl.msg(data)
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
    done : Unit <- WSM.client_on_insecure(~h.cl, "127.0.0.1", 19894, "/chat", "dGhlIHNhbXBsZSBub25jZQ==")
    z : Unit <- IO.die(Unit, 0, "")
    return 0
