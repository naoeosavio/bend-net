# WSS fragment echo client (task-020 phase 1, manual interop only).
# Sends one 32000-byte binary message to a Node `ws` echo peer on
# 127.0.0.1:19894 and prints 1 when the full echo lands (0 otherwise).
# The payload rides two 16KB chunks: `bend run` faults past ~25KB on a
# single replicate-built list, so run this through a built binary:
# bend examples/wss_frag_client.bend -o /tmp/frag_client_bin &&
#   /tmp/frag_client_bin
# Manual only — not in check.sh.
import Base
import ../lib/ws.bend as WS
import ../lib/wss.bend as WSS

law big_msg:
  List<&2, U32>

def big_msg():
  List.append(&2, U32, List.replicate(U32, 16000n, 97), List.replicate(U32, 16000n, 98))

law cl.msg.go:
  for +data: List<&2, U32>
  for ok: Bool
  IO(WS.WSOut)

def cl.msg.go(data, ok):
  match ok:
    case True{}:
      do IO<WS.WSOut>:
        w : Unit <- IO.print("1")
        return WS.out_close([])
    case False{}:
      do IO<WS.WSOut>:
        w : Unit <- IO.print("0")
        return WS.out_close([])

law cl.msg:
  for +data: List<&2, U32>
  IO(WS.WSOut)

def cl.msg(data):
  cl.msg.go(data, U32.is_eq(U32.from_nat(List.length(&2, U32, data)), 32000))

law h.cl:
  for ev: WS.WSEv
  IO(WS.WSOut)

def h.cl(ev):
  match ev:
    case WS.EvOpen{}:
      IO.pure(WS.WSOut, WS.OutMsg{WS.WSBin{big_msg()}})
    case WS.EvMsg{msg}:
      match msg:
        case WS.WSText{text}:
          do IO<WS.WSOut>:
            w : Unit <- IO.print("0")
            return WS.out_close([])
        case WS.WSBin{data}:
          cl.msg(data)
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
    done : Unit <- WSS.client.on_insecure(~h.cl, "127.0.0.1", 19894, "/chat", "dGhlIHNhbXBsZSBub25jZQ==")
    z : Unit <- IO.die(Unit, 0, "")
    return 0
