# WSS subprotocol echo server (task-020 phase 2, manual interop only).
# Supports ["p1"] via WSM.server_on_sub on 127.0.0.1:19894 (TLS test
# certs). Prints LISTEN, then DONE on hello echo. Run through a built
# binary (bend run faults on large transfers, not needed here):
# bend examples/wsm_sub_echo.bend -o /tmp/sub_echo_bin && /tmp/sub_echo_bin
# Manual only — not in check.sh.
import Base
import ../lib/wsm.bend as WSM
import ../lib/tcp.bend as TCP

law h.echo:
  for ev: WSM.WSEv
  IO(WSM.WSOut)

def h.echo(ev):
  match ev:
    case WSM.EvOpen{}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})
    case WSM.EvMsg{msg}:
      match msg:
        case WSM.WSText{text}:
          +txt = text
          do IO<WSM.WSOut>:
            w : Unit <- IO.print("GOT " ++ txt)
            return WSM.OutMsg{WSM.WSText{txt}}
        case WSM.WSBin{data}:
          IO.pure(WSM.WSOut, WSM.OutMsg{msg})
    case WSM.EvPing{pay}:
      IO.pure(WSM.WSOut, WSM.wsm_out_pong(pay))
    case WSM.EvPong{pay}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})
    case WSM.EvClose{pay}:
      do IO<WSM.WSOut>:
        w : Unit <- IO.print("DONE sub")
        return WSM.wsm_out_close([])
    case WSM.EvError{code, msg}:
      do IO<WSM.WSOut>:
        w : Unit <- IO.print("FAIL sub")
        return WSM.OutRaw{[]}

law main_go:
  for r: Result<&1, &1, U32 & String, Listener>
  IO(U32)

def main_go(r):
  match r:
    case Fail{e}:
      do IO<U32>:
        w : Unit <- IO.print("listen fail")
        return 1
    case Done{l}:
      do IO<U32>:
        w : Unit <- IO.print("LISTEN 19894")
        z : Unit <- WSM.server_on_sub(~h.echo, ["p1"], l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
        return 0

law main:
  IO(U32)

def main():
  do IO<U32>:
    r : Result<&1, &1, U32 & String, Listener> <- TCP.listen(19894)
    main_go(r)
