# The browser leg's two servers (tests/rfc/browser.html), in one program:
#
#   http://127.0.0.1:19881/echo   POST, byte echo
#   http://127.0.0.1:19881/chunk  GET, the body "Wikipedia"
#   http://127.0.0.1:19881/close  GET, Connection: close
#   ws://127.0.0.1:19884/chat     echo, "chat" subprotocol
#
# The page is opened from file://, so every fetch is cross-origin and the
# H1 answers carry Access-Control-Allow-Origin. The page asks for the
# "chat" subprotocol, and a browser fails the handshake when the 101 does
# not echo a requested protocol, so the WS side uses the subprotocol-aware
# entry with it as the wanted one. Both are the same requirements the
# oracle recipe in tests/rfc/browser.html has (h1_oracle.js sets the CORS
# header, ws_oracle.js echoes the first requested protocol).
#
# Manual only (two fixed ports, blocks until Ctrl-C):
#   bend examples/httpx/browser_leg.bend
#   open tests/rfc/browser.html and press the two buttons
#
# Mirror of .p42/browser_h1.bend + .p42/browser_ws.bend, the scratch pair
# the browser leg was first run against; this file is the shipped recipe.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX
import ../../lib/wsm.bend as WSM

def cors() -> List<&2, HTTPX.Hdr>:
  [HTTPX.Hdr{"Access-Control-Allow-Origin", "*"}]

def close_hdrs() -> List<&2, HTTPX.Hdr>:
  [HTTPX.Hdr{"Access-Control-Allow-Origin", "*"}, HTTPX.Hdr{"Connection", "close"}]

def txt(s: String) -> List<&2, U32>:
  HTTPX.x_str_bytes(s)

def is_echo(path: String) -> Bool:
  String.eq(path, "/echo")

def is_chunk(path: String) -> Bool:
  String.eq(path, "/chunk")

def is_close(path: String) -> Bool:
  String.eq(path, "/close")

def route_go(is_echo: Bool, is_chunk: Bool, is_close: Bool, +body: List<&2, U32>) -> HTTPX.Response:
  match is_echo is_chunk is_close:
    case True{} _ _:
      HTTPX.Response{200, cors(), body}
    case _ True{} _:
      HTTPX.Response{200, cors(), txt("Wikipedia")}
    case _ _ True{}:
      HTTPX.Response{200, close_hdrs(), txt("bye")}
    case _ _ _:
      HTTPX.Response{404, cors(), Nil{}}

def h1_h(req: HTTPX.Request) -> IO(HTTPX.Response):
  match req:
    case HTTPX.Request{method, +path, headers, body}:
      IO.pure(HTTPX.Response, route_go(is_echo(path), is_chunk(path), is_close(path), body))

def ws_h(ev: WSM.WSEv) -> IO(WSM.WSOut):
  match ev:
    case WSM.EvMsg{msg}:
      IO.pure(WSM.WSOut, WSM.OutMsg{msg})
    case WSM.EvPing{pay}:
      IO.pure(WSM.WSOut, WSM.OutOp{10, pay})
    case _:
      IO.pure(WSM.WSOut, WSM.OutRaw{Nil{}})

def listen_ok(r: Result<&1, &1, U32 & String, Listener>) -> IO(Listener):
  match r:
    case Fail{e}:
      IO.die(Listener, 1, "listen failed")
    case Done{l}:
      IO.pure(Listener, l)

def h1_side(l: Listener) -> IO(Unit):
  HTTPX.server.on_h1_plain(~h1_h, l)

def main() -> IO(U32):
  do IO<U32>:
    r1 : Result<&1, &1, U32 & String, Listener> <- TCP.listen(19881)
    l1 : Listener <- listen_ok(r1)
    r2 : Result<&1, &1, U32 & String, Listener> <- TCP.listen(19884)
    l2 : Listener <- listen_ok(r2)
    c : Chan(Unit) <- IO.fork(Unit, h1_side(l1))
    z : Unit <- WSM.server_on_sub_plain(~ws_h, ["chat"], l2)
    return 0
