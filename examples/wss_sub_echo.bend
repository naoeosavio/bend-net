# WSS subprotocol echo server (task-020 phase 2, manual interop only).
# Supports ["p1"] via WSS.server_on_sub on 127.0.0.1:19894 (TLS test
# certs). Prints LISTEN, then DONE on hello echo. Run through a built
# binary (bend run faults on large transfers, not needed here):
# bend examples/wss_sub_echo.bend -o /tmp/sub_echo_bin && /tmp/sub_echo_bin
# Manual only — not in check.sh.
import Base
import ../lib/ws.bend as WS
import ../lib/wss.bend as WSS
import ../lib/tcp.bend as TCP

law h.echo:
  for ev: WS.WSEv
  IO(WS.WSOut)

def h.echo(ev):
  match ev:
    case WS.EvOpen{}:
      IO.pure(WS.WSOut, WS.OutRaw{[]})
    case WS.EvMsg{msg}:
      match msg:
        case WS.WSText{text}:
          +txt = text
          do IO<WS.WSOut>:
            w : Unit <- IO.print("GOT " ++ txt)
            return WS.OutMsg{WS.WSText{txt}}
        case WS.WSBin{data}:
          IO.pure(WS.WSOut, WS.OutMsg{msg})
    case WS.EvPing{pay}:
      IO.pure(WS.WSOut, WS.out_pong(pay))
    case WS.EvPong{pay}:
      IO.pure(WS.WSOut, WS.OutRaw{[]})
    case WS.EvClose{pay}:
      do IO<WS.WSOut>:
        w : Unit <- IO.print("DONE sub")
        return WS.out_close([])
    case WS.EvError{code, msg}:
      do IO<WS.WSOut>:
        w : Unit <- IO.print("FAIL sub")
        return WS.OutRaw{[]}

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
        z : Unit <- WSS.server_on_sub(~h.echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem", ["p1"])
        return 0

law main:
  IO(U32)

def main():
  do IO<U32>:
    r : Result<&1, &1, U32 & String, Listener> <- TCP.listen(19894)
    main_go(r)
