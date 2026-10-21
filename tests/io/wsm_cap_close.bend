# io (wsm_cap_close): a frame header declaring more than
# WSM.wsm_max_payload() must be answered with CLOSE 1009 (message too
# big), not with the unregistered 1017 the cap close used to carry
# (task-042 phase 0, bug 2 of the audit).
#
# The peer is the same raw hand-written socket as in wsm_ctrl_frag: it
# upgrades, then writes ONLY the 14-byte masked header (2 + 8-byte
# extended length + 4-byte mask) that declares wsm_max_payload() + 1 and
# no payload at all. The cap is decided by the declared length, so the
# server answers the close before any body byte is due -- which keeps the
# read deterministic: with a real oversized payload the server closes
# while the peer is still writing and the RST erases the queued close.
#
# 1009 is [3, 241] on the wire; [3, 249] is 1017, which RFC 6455 never
# registers and `ws` (isValidStatusCode 1000-1014) and browsers reject,
# turning the "message too big" answer into a protocol error.
#
# Score: op 8 x payload [3, 241], golden 1.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/http.bend as HTTP
import ../../lib/wsm.bend as WSM

def PORT() -> U32:
  19592

def CLI_PATH() -> String:
  "/chat"

def CLI_KEY() -> String:
  "dGhlIHNhbXBsZSBub25jZQ=="

def CLOSE_TOO_BIG() -> List<&2, U32>:
  [3, 241]

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# The 14-byte header from the library's own masked writer: payload list
# empty, so wsm_show_masked_head.go emits the header alone. is_small and
# is_med are both False (8-byte length), and the declared length is one
# past the cap, which is what the split rejects with 413.
def cap_head() -> List<&2, U32>:
  +len = (WSM.wsm_max_payload() + 1 : U32)
  WSM.wsm_show_masked_head.go(True{}, 2, len, [], 1, 2, 3, 4, False{}, False{})

# Print the score and stop the run: the forked server parks in accept, so
# every server_on test exits through IO.die (code 0, no extra line).
def cli_dead(s: Socket, score: U32) -> IO(Unit):
  do IO<Unit>:
    x : Unit <- Socket.close(s)
    w : Unit <- IO.print(U32.show(score))
    z : Unit <- IO.die(Unit, 0, "")
    return z

# A step before the socket exists (dial or head builder failed): print
# the failing score so the golden diff shows it, then stop.
def cli_none() -> IO(Unit):
  do IO<Unit>:
    w : Unit <- IO.print("0")
    z : Unit <- IO.die(Unit, 0, "")
    return z

# The close arrived: score op 8 with a 1009 payload.
def cli_close(m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>) -> IO(Unit):
  (s2, r, rest) = m
  match r:
    case Fail{e}:
      cli_dead(s2, 0)
    case Done{t}:
      (fin, op, pay) = t
      cli_dead(s2, U32.mul(b2u(U32.is_eq(op, 8)), HTTP.x_eq(pay, CLOSE_TOO_BIG())))

# The header is on the wire: read the answer, whose rest seeds nothing
# because the header is the last thing this peer writes.
def cli_sent(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      cli_dead(s, 0)
    case Done{u}:
      do IO<Unit>:
        m2 : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- WSM.recv_op_client_framed_plain(s, [])
        cli_close(m2)

# Upgrade accepted: write the oversized header alone.
def cli_hs_ok(s: Socket, ok: U32) -> IO(Unit):
  match ok:
    case 1:
      do IO<Unit>:
        m : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send_bytes(s, cap_head())
        cli_sent(m)
    case _:
      cli_dead(s, 0)

# The 101 head arrived; only a validated upgrade moves on.
def cli_hs(m: Socket & Result<&1, &1, U32 & String, String>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      cli_dead(s, 0)
    case Done{resp}:
      cli_hs_ok(s, b2u(String.contains(resp, "101")))

# The upgrade request is out: read the head.
def cli_hs_sent(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      cli_dead(s, 0)
    case Done{u}:
      do IO<Unit>:
        got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 8192)
        cli_hs(got)

def cli_open(conn: Result<&1, &1, U32 & String, Socket>, req_txt: String) -> IO(Unit):
  match conn:
    case Fail{e}:
      cli_none()
    case Done{sock}:
      do IO<Unit>:
        m : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req_txt)
        cli_hs_sent(m)

def cli_start(host: String, port: U32, req: Result<&1, &1, U32 & String, String>) -> IO(Unit):
  match req:
    case Fail{e}:
      cli_none()
    case Done{req_txt}:
      do IO<Unit>:
        conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect(host, port)
        cli_open(conn, req_txt)

# Server: echo every data message, answer controls, close on close. The
# 413 path never reaches this handler (the loop answers the cap close).
def h.srv(ev: WSM.WSEv) -> IO(WSM.WSOut):
  match ev:
    case WSM.EvOpen{}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})
    case WSM.EvMsg{msg}:
      match msg:
        case WSM.WSText{text}:
          IO.pure(WSM.WSOut, WSM.OutMsg{WSM.WSText{text}})
        case WSM.WSBin{data}:
          IO.pure(WSM.WSOut, WSM.OutMsg{WSM.WSBin{data}})
    case WSM.EvPing{pay}:
      IO.pure(WSM.WSOut, WSM.wsm_out_pong(pay))
    case WSM.EvPong{pay}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})
    case WSM.EvClose{pay}:
      IO.pure(WSM.WSOut, WSM.wsm_out_close(pay))
    case WSM.EvError{code, msg}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})

def listen_retry(port: U32, r: Result<&1, &1, (U32 & String), Listener>, rest: IO(Listener & U32)) -> IO(Listener & U32):
  match r:
    case Done{l}:
      IO.pure(Listener & U32, (l, port))
    case Fail{e}:
      rest

def listen_any(tries: Nat, +port: U32) -> IO(Listener & U32):
  match tries:
    case 0n:
      IO.die(Listener & U32, 1, "no free tcp port")
    case 1n+t:
      rest = listen_any(t, (port + 1 : U32))
      do IO<Listener & U32>:
        r : Result<&1, &1, (U32 & String), Listener> <- TCP.listen(port)
        listen_retry(port, r, rest)

def server_side(l: Listener) -> IO(Unit):
  do IO<Unit>:
    z : Unit <- WSM.server_on_plain(~h.srv, l)
    return z

def run(l: Listener, +port: U32) -> IO(Unit):
  do IO<Unit>:
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l))
    done : Unit <- cli_start("127.0.0.1", port, WSM.wsm_client_head("127.0.0.1", port, CLI_PATH(), CLI_KEY()))
    z : Unit <- IO.die(Unit, 0, "")
    return z

def run_bound(b: Listener & U32) -> IO(Unit):
  (l, port) = b
  run(l, port)

def main() -> IO(Unit):
  do IO<Unit>:
    b : Listener & U32 <- listen_any(32n, PORT())
    run_bound(b)

#|1
