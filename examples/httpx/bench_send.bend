# examples/httpx/bench_send.bend
#
# Manual bench of the send path (task-065 phase 5): how much of one DATA
# frame send is the TLS twin, and how much is the seal. Three rows send
# the same 1 MiB in frames of 16393 cells (nine header bytes and a 16 KiB
# payload). The walk row sends nothing, so it is the floor of the pump's
# length walk:
#   walk      HTTP.x_len32 per frame, the Bend-level walk
#   tcp_send  TCPB.send_bytes per frame: the twin pack and one write
#   tls_send  TLS.tls_send_bytes per frame: the pack, the seal and the write
# Build a binary before you run it: the wire runs the C twin, and
# `bend <file>` runs the JS twin instead.
#   bend examples/httpx/bench_send.bend -o bench_send.bin
#   ./bench_send.bin [frame]
# A peer thread drains every row and answers the bytes it read, so a row
# that lost bytes fails its chk line. Tag 0 is the raw TCP row, tag 1 the
# TLS row: one def per step serves both, so the peers keep one shape.
import Base
import ../../lib/http.bend as HTTP
import ../../lib/http2.bend as HTTP2
import ../../lib/tcp.bend as TCPB
import ../../lib/tls.bend as TLS

# Timed rounds per row: 5 rounds of 1 MiB, the test.bend shape.
def ROUNDS() -> Nat:
  5n

# Frames of one round: 64 frames of 16 KiB are 1 MiB, the wire shape.
def FRAMES() -> Nat:
  64n

# Payload of one frame: the H2 frame cap.
def FRAME_DEFAULT() -> U32:
  16384

# Read ceiling of the peer drain.
def DRAIN_MAX() -> U32:
  65536

# Reads one peer waits before it gives up on the client.
def DRAIN_FUEL() -> Nat:
  4096n

def PORT_TCP() -> U32:
  19993

def PORT_TLS() -> U32:
  19994

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# First minimum: any round above this would have tripped first.
def RUN_MIN_INIT() -> Nat:
  600000n

# Widest label, keeps the dots aligned.
def CHECK_WIDTH() -> Nat:
  22n

def dots(n: Nat) -> String:
  match n:
    case 0n:
      ""
    case 1n+p:
      String.append(".", dots(p))

def pad_name(+name: String) -> String:
  String.append(name, dots(Nat.sub(CHECK_WIDTH(), String.length(name))))

def show_check(name: String, ok: Bool, got: U32, want: U32) -> IO(Unit):
  match ok:
    case True{}:
      IO.print(pad_name(name) ++ " ok")
    case False{}:
      +seen : String = " FAIL got=" ++ U32.show(got)
      +due : String = " want=" ++ U32.show(want)
      IO.print(pad_name(name) ++ seen ++ due)

# Builds n payload bytes, tail-recursive (the test.bend build_flat shape).
def build_go(+n: Nat, +i: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      build_go(p, (i + 1 : U32), U32.and(i, 255) <> acc)

def build(n: U32) -> List<&2, U32>:
  build_go(U32.to_nat(n), 0, Nil{})

# Folds one sample into min, max, total ms (the test.bend shape).
def fold_go(+el: Nat, mn: Nat, rest: Nat & Nat) -> Nat & (Nat & Nat):
  match rest:
    case (mx, tot):
      (Nat.min(el, mn), (Nat.max(el, mx), (el + tot : Nat)))

def fold_el(el: Nat, st: Nat & (Nat & Nat)) -> Nat & (Nat & Nat):
  match st:
    case (mn, rest):
      fold_go(el, mn, rest)

def show_stats_go(+name: String, per_round: U32, mn: Nat, rest: Nat & Nat) -> IO(Unit):
  match rest:
    case (mx, tot):
      +avg : Nat = Nat.div(tot, ROUNDS())
      +us : Nat = Nat.mul(Nat.max(avg, 1n), 1048576n)
      +rate : Nat = Nat.div(Nat.mul(U32.to_nat(per_round), 1000n), us)
      +head : String = pad_name(name) ++ " avg=" ++ Nat.show(avg) ++ "ms"
      +lo : String = " -" ++ Nat.show(Nat.sub(avg, mn))
      +hi : String = " +" ++ Nat.show(Nat.sub(mx, avg))
      IO.print(head ++ lo ++ hi ++ " " ++ Nat.show(rate) ++ "MB/s")

def report(+name: String, per_round: U32, +want: U32, +got: U32, msst: Nat & (Nat & Nat)) -> IO(Unit):
  match msst:
    case (mn, rest):
      do IO<Unit>:
        a : Unit <- show_stats_go(name, per_round, mn, rest)
        show_check(String.append("chk_", name), U32.is_eq(got, want), got, want)

# --- row walk: the Bend-level length walk, no IO ----------------------
# The stamp cell keeps the walk inside the loop. A walk of an invariant
# list is hoisted out: the row then answers one walk per round and reads
# 3x fast (test.bend: an unobserved sample measures 0ms).

def walk_n(+frame: List<&2, U32>, left: Nat, +acc: U32) -> U32:
  match left:
    case 0n:
      acc
    case 1n+p:
      walk_n(frame, p, (acc + U32.sub(HTTP.x_len32(U32.and(acc, 1) <> frame), 1) : U32))

def walk_rounds(name: String, +frame: List<&2, U32>, per_round: U32, want: U32, left: Nat, msst: Nat & (Nat & Nat), chk: U32) -> IO(Unit):
  match left:
    case 0n:
      report(name, per_round, want, chk, msst)
    case 1n+p:
      do IO<Unit>:
        t0 : Nat <- IO.now()
        n : U32 = walk_n(frame, FRAMES(), 0)
        t1 : Nat <- IO.now()
        walk_rounds(name, frame, per_round, want, p, fold_el(Nat.sub(t1, t0), msst), (chk + n : U32))

# --- rows tcp_send and tls_send: the twin, with and without the seal --

# Sends FRAMES frames on one connection. A bench has nothing to retry,
# so a failed send exits with the eff's own code.
@unsafe
def frame_n(left: Nat, tag: U32, sock: Socket, +frame: List<&2, U32>) -> IO(Socket):
  match left tag:
    case 0n _:
      IO.pure(Socket, sock)
    case 1n+p 0:
      do IO<Socket>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCPB.send_bytes(sock, frame)
        frame_next(tag, sent, frame, p)
    case 1n+p _:
      do IO<Socket>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(sock, frame)
        frame_next(tag, sent, frame, p)

@unsafe
def frame_next(tag: U32, sent: Socket & Result<&1, &1, U32 & String, Unit>, +frame: List<&2, U32>, left: Nat) -> IO(Socket):
  (s2, r) = sent
  match r:
    case Fail{(code, msg)}:
      IO.die(Socket, code, msg)
    case Done{u}:
      frame_n(left, tag, s2, frame)

# Times FRAMES sends per round.
def rounds_n(left: Nat, +tag: U32, sock: Socket, +frame: List<&2, U32>, msst: Nat & (Nat & Nat)) -> IO(Nat & (Nat & Nat)):
  match left:
    case 0n:
      # shortcut: the row leaves the client socket open, one fd per row,
      # and the process exit closes it. Close it here only if the bench
      # grows a loop over rows.
      IO.pure(Nat & (Nat & Nat), msst)
    case 1n+p:
      do IO<Nat & (Nat & Nat)>:
        t0 : Nat <- IO.now()
        s2 : Socket <- frame_n(FRAMES(), tag, sock, frame)
        t1 : Nat <- IO.now()
        rounds_n(p, tag, s2, frame, fold_el(Nat.sub(t1, t0), msst))

# --- peers: drain the connection and answer the bytes -----------------
# The peer stops when it holds `want` bytes, so a row does not wait for
# the client to close. The fuel bounds the reads: a peer that stops first
# answers a short count and the chk line fails.

def peer_close(tag: U32, sock: Socket, got: U32) -> IO(U32):
  match tag:
    case 0:
      do IO<U32>:
        x : Unit <- Socket.close(sock)
        return got
    case _:
      do IO<U32>:
        x : Unit <- TLS.tls_close(sock)
        return got

@unsafe
def peer_got(tag: U32, left: Nat, r: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, got: U32, +want: U32) -> IO(U32):
  (s2, g2) = r
  match g2:
    case Fail{(code, msg)}:
      do IO<U32>:
        a : Unit <- IO.print("peer read failed code=" ++ U32.show(code))
        peer_close(tag, s2, got)
    case Done{bs}:
      +nb : U32 = (got + HTTP.x_len32(bs) : U32)
      peer_read(left, U32.is_ge(nb, want), tag, s2, nb, want)

@unsafe
def peer_read(left: Nat, stop: Bool, tag: U32, sock: Socket, +got: U32, want: U32) -> IO(U32):
  match left stop:
    case 0n _:
      do IO<U32>:
        a : Unit <- IO.print("peer fuel out got=" ++ U32.show(got))
        peer_close(tag, sock, got)
    case 1n+p True{}:
      peer_close(tag, sock, got)
    case 1n+p False{}:
      match tag:
        case 0:
          do IO<U32>:
            r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TCPB.recv_bytes(sock, DRAIN_MAX())
            peer_got(tag, p, r, got, want)
        case _:
          do IO<U32>:
            r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(sock, DRAIN_MAX())
            peer_got(tag, p, r, got, want)

@unsafe
def peer_acc(tag: U32, m: Listener & Result<&1, &1, U32 & String, Socket>, want: U32) -> IO(U32):
  (l2, r) = m
  match r:
    case Fail{(code, msg)}:
      IO.die(U32, code, msg)
    case Done{sock}:
      do IO<U32>:
        x : Unit <- Listener.close(l2)
        peer_read(DRAIN_FUEL(), False{}, tag, sock, 0, want)

@unsafe
def peer_conn(tag: U32, l: Listener, want: U32) -> IO(U32):
  match tag:
    case 0:
      do IO<U32>:
        m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
        peer_acc(tag, m, want)
    case _:
      do IO<U32>:
        m : Listener & Result<&1, &1, U32 & String, Socket> <- TLS.tls_accept(l, CERT(), KEY())
        peer_acc(tag, m, want)

# --- the two rows and the entry ---------------------------------------

def port_of(tag: U32) -> U32:
  match tag:
    case 0:
      PORT_TCP()
    case _:
      PORT_TLS()

def listen_of(tag: U32) -> IO(Listener):
  do IO<Listener>:
    lr : Result<&1, &1, U32 & String, Listener> <- TCPB.listen_backlog(port_of(tag), TCPB.LISTEN_BACKLOG())
    IO.pass(Listener, lr)

def connect_of(tag: U32) -> IO(Socket):
  match tag:
    case 0:
      do IO<Socket>:
        cr : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", port_of(tag))
        IO.pass(Socket, cr)
    case _:
      do IO<Socket>:
        cr : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_insecure("127.0.0.1", port_of(tag))
        IO.pass(Socket, cr)

def row(+tag: U32, name: String, +frame: List<&2, U32>, per_round: U32, +want: U32) -> IO(Unit):
  do IO<Unit>:
    l : Listener <- listen_of(tag)
    chan : Chan(U32) <- IO.fork(U32, peer_conn(tag, l, want))
    sock : Socket <- connect_of(tag)
    msst : Nat & (Nat & Nat) <- rounds_n(ROUNDS(), tag, sock, frame, (RUN_MIN_INIT(), (0n, 0n)))
    got : U32 <- IO.join(U32, chan)
    report(name, per_round, want, got, msst)

def u32_go(m: Maybe<&2, U32>, +dflt: U32) -> U32:
  match m:
    case None{}:
      dflt
    case Some{v}:
      v

def size_of(xs: List<String>, +dflt: U32) -> U32:
  match xs:
    case Nil{}:
      dflt
    case +h <> t:
      u32_go(U32.read(h), dflt)

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    +n : U32 = size_of(args, FRAME_DEFAULT())
    +frame : List<&2, U32> = HTTP2.x_frame_write_len(0, 0, 1, build(n), n)
    +flen : U32 = HTTP.x_len32(frame)
    +per : U32 = U32.mul(flen, U32.from_nat(FRAMES()))
    +want : U32 = U32.mul(per, U32.from_nat(ROUNDS()))
    IO.print("frame=" ++ U32.show(flen) ++ " frames=" ++ Nat.show(FRAMES()) ++ " rounds=" ++ Nat.show(ROUNDS()))
    a : Unit <- walk_rounds("walk", frame, per, want, ROUNDS(), (RUN_MIN_INIT(), (0n, 0n)), 0)
    b : Unit <- row(0, "tcp_send", frame, per, want)
    c : Unit <- row(1, "tls_send", frame, per, want)
    IO.pure(Unit, c)

# Rows to read on an idle box, binary against binary (the `-o` build):
# the delta between tcp_send and tls_send is the TLS share of one frame,
# and the delta between walk and tcp_send is the twin's walk share.
