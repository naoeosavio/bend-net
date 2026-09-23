# WSS fragment echo server (task-020 phase 1, manual interop only).
# Echoes any message verbatim on 127.0.0.1:19893 (TLS test certs) so a
# Node `ws` peer can push >16KB payloads through, forcing real
# fragmentation on the wire. Prints each message length. Run through a
# built binary (`bend run` faults past ~25KB single transfers):
# bend examples/wss_frag_echo.bend -o /tmp/frag_echo_bin &&
#   /tmp/frag_echo_bin   (Ctrl-C to stop)
# Manual only — not in check.sh.
import Base
import ../lib/ws.bend as WS
import ../lib/wss.bend as WSS
import ../lib/tcp.bend as TCP

law h.len.go:
  for n: U32
  IO(WS.WSOut)

def h.len.go(n):
  do IO<WS.WSOut>:
    w : Unit <- IO.print(U32.show(n))
    return WS.OutRaw{[]}

law h.len:
  for +data: List<&2, U32>
  IO(WS.WSOut)

def h.len(data):
  h.len.go(U32.from_nat(List.length(&2, U32, data)))

law h.code.go:
  for code: U32
  IO(WS.WSOut)

def h.code.go(code):
  do IO<WS.WSOut>:
    w : Unit <- IO.print(U32.show(code))
    return WS.OutRaw{[]}

law h.code:
  for code: U32
  IO(WS.WSOut)

def h.code(code):
  h.code.go(code)

law h.echo2.go:
  for +data: List<&2, U32>
  for n: U32
  IO(WS.WSOut)

def h.echo2.go(data, n):
  do IO<WS.WSOut>:
    w : Unit <- IO.print(U32.show(n))
    return WS.OutMsg{WS.WSBin{data}}

law h.echo2.len:
  for +data: List<&2, U32>
  U32

def h.echo2.len(data):
  U32.from_nat(List.length(&2, U32, data))

law h.echo2:
  for +data: List<&2, U32>
  IO(WS.WSOut)

def h.echo2(data):
  h.echo2.go(data, h.echo2.len(data))

law h.echo3.go:
  for +pay: List<&2, U32>
  for n: U32
  IO(WS.WSOut)

def h.echo3.go(pay, n):
  do IO<WS.WSOut>:
    w : Unit <- IO.print(U32.show(n))
    return WS.out_close(pay)

law h.echo3.len:
  for +pay: List<&2, U32>
  U32

def h.echo3.len(pay):
  U32.from_nat(List.length(&2, U32, pay))

law h.echo3:
  for +pay: List<&2, U32>
  IO(WS.WSOut)

def h.echo3(pay):
  h.echo3.go(pay, h.echo3.len(pay))

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
          do IO<WS.WSOut>:
            w : Unit <- IO.print("srv-text")
            return WS.OutMsg{msg}
        case WS.WSBin{data}:
          h.echo2(data)
    case WS.EvPing{pay}:
      IO.pure(WS.WSOut, WS.out_pong(pay))
    case WS.EvPong{pay}:
      IO.pure(WS.WSOut, WS.OutRaw{[]})
    case WS.EvClose{pay}:
      h.echo3(pay)
    case WS.EvError{code, msg}:
      h.code(code)

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
        w : Unit <- IO.print("LISTEN 19893")
        z : Unit <- WSS.server_on(~h.echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
        return 0

law main:
  IO(U32)

def main():
  do IO<U32>:
    r : Result<&1, &1, U32 & String, Listener> <- TCP.listen(19893)
    main_go(r)
