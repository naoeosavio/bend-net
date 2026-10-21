# io (wsm_frag_coalesce): bytes buffered past a fragment frame must
# survive the fragment step (task-042 phase 0, bug discovered while
# reproducing bug 1).
#
# wsm_loop keeps the bytes a read returned past the frame it split in
# its `buf` parameter, and state 2 hands them back to the next read --
# except on the StepFrag arm, which reads with the (empty) rest of `mf`
# and asks the socket again. When a peer coalesces an opening fragment
# and its continuation in ONE write (a browser does), the continuation
# is already in user space, the socket has nothing left, and the session
# parks forever: neither the echo nor a close ever comes back.
#
# The peer proves it with a masked TEXT(fin=0,"he") + CONT(fin=1,"llo")
# in one write, then -- after the pause -- a masked CLOSE. While the
# buffered continuation is dropped, the close is the first frame the
# loop sees, so the peer reads the close answer (op 8) and scores 0.
# Once the continuation is read from the buffer, the stitched "hello"
# is echoed first and the score is 1.
#
# Score: op 1 x payload "hello", golden 1.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/http.bend as HTTP
import ../../lib/wsm.bend as WSM

def PORT() -> U32:
  19593

# Milliseconds before the close: the server is parked in recv by then, so
# the close cannot ride the same segment as the coalesced frames.
def SYNC_MS() -> U32:
  100

def CLI_PATH() -> String:
  "/chat"

def CLI_KEY() -> String:
  "dGhlIHNhbXBsZSBub25jZQ=="

# Pinned mask key: this peer builds its frames by hand, so the key is
# fixed instead of drawn from the entropy pool.
def FX_KEY() -> WSM.WSMask:
  WSM.WSMask{1, 2, 3, 4}

def TEXT_HEAD() -> List<&2, U32>:
  [104, 101]

def TEXT_TAIL() -> List<&2, U32>:
  [108, 108, 111]

def TEXT_ALL() -> List<&2, U32>:
  List.append(&2, U32, TEXT_HEAD(), TEXT_TAIL())

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

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

# First reply: the echo of the stitched message (or the close answer
# while the buffered continuation is dropped). Score = op 1 x payload.
def cli_echo(m: Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32>) -> IO(Unit):
  (s, r, rest) = m
  match r:
    case Fail{e}:
      cli_dead(s, 0)
    case Done{t}:
      (fin, op, pay) = t
      cli_dead(s, U32.mul(b2u(U32.is_eq(op, 1)), HTTP.x_eq(pay, TEXT_ALL())))

# The close is out: read the first reply.
def cli_close_sent(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      cli_dead(s, 0)
    case Done{u}:
      do IO<Unit>:
        m2 : Socket & Result<&1, &1, U32 & String, Bool & U32 & List<&2, U32>> & List<&2, U32> <- WSM.recv_op_client_framed_plain(s, [])
        cli_echo(m2)

# The coalesced frames are out: pause, then close so the loop has one
# more frame to read whether or not it kept the continuation.
def cli_pause(s: Socket) -> IO(Unit):
  do IO<Unit>:
    w : Unit <- IO.sleep(SYNC_MS())
    bye : List<&2, U32> <- IO.pass(List<&2, U32>, WSM.wsm_show_masked_key(True{}, 8, [], FX_KEY()))
    m : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send_bytes(s, bye)
    cli_close_sent(m)

def cli_frames_sent(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, r) = m
  match r:
    case Fail{e}:
      cli_dead(s, 0)
    case Done{u}:
      cli_pause(s)

# Upgrade accepted: write the two fragments in ONE write.
def cli_send(s: Socket) -> IO(Unit):
  do IO<Unit>:
    one : List<&2, U32> <- IO.pass(List<&2, U32>, WSM.wsm_show_masked_key(False{}, 1, TEXT_HEAD(), FX_KEY()))
    two : List<&2, U32> <- IO.pass(List<&2, U32>, WSM.wsm_show_masked_key(True{}, 0, TEXT_TAIL(), FX_KEY()))
    m : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send_bytes(s, List.append(&2, U32, one, two))
    cli_frames_sent(m)

# The 101 head arrived; only a validated upgrade moves on.
def cli_hs_ok(s: Socket, ok: U32) -> IO(Unit):
  match ok:
    case 1:
      cli_send(s)
    case _:
      cli_dead(s, 0)

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

# Server: echo every data message, answer controls, close on close.
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
