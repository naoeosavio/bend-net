# lib (lib_tls_bench): the TLS twins measured the way test.bend measures
# the list ops -- BENCH_RUNS timed runs with IO.now(), the average with
# its min/max spread, and a checksum that proves the work was observed
# (the compiler erases unobserved work; test.bend explains it at its
# footer). Loopback and self-signed, so no network is involved.
#
# Baseline taken 2026-10-12 with the OpenSSL twins (bun:ffi), before the
# native `tls` rewrite: tls_connect_echo avg=... (see the task file).
import Base
import ../../lib/tls.bend as TLS

# Timed runs per column: 10 matches test.bend, so the spread reads alike.
def BENCH_RUNS() -> Nat:
  10n

# First minimum: any single run above this would have tripped first.
def RUN_MIN_INIT() -> Nat:
  60000n

# Echo payload ("hello") and its length.
def PAYLOAD() -> List<&2, U32>:
  [104, 101, 108, 108, 111]

def PAYLOAD_LEN() -> U32:
  5

# Expected checksum: one point per run that echoed the payload back.
def EXPECTED() -> U32:
  U32.from_nat(BENCH_RUNS())

def ECHO_PORT() -> U32:
  19992

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# Counts a Bool as 0 or 1.
def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

law bytes_eq:
  for a: List<&2, U32>
  for b: List<&2, U32>
  U32

def bytes_eq(a, b):
  match a b:
    case Nil{} Nil{}:
      1
    case h1 <> t1 h2 <> t2:
      (b2u(U32.is_eq(h1, h2)) * bytes_eq(t1, t2) : U32)
    case _ _:
      0

law score_echo:
  for r: Result<&1, &1, (U32 & String), List<&2, U32>>
  U32

def score_echo(r):
  match r:
    case Fail{e}:
      0
    case Done{bs}:
      bytes_eq(bs, PAYLOAD())

# Listener, retrying the port when it is taken.
law listen_retry:
  for port: U32
  for r: Result<&1, &1, (U32 & String), Listener>
  for rest: IO(Listener & U32)
  IO(Listener & U32)

def listen_retry(port, r, rest):
  match r:
    case Done{l}:
      IO.pure(Listener & U32, (l, port))
    case Fail{e}:
      rest

law listen_any:
  for tries: Nat
  for +port: U32
  IO(Listener & U32)

def listen_any(tries, port):
  match tries:
    case 0n:
      IO.die(Listener & U32, 1, "no free tcp port")
    case 1n+t:
      rest = listen_any(t, (port + 1 : U32))
      do IO<Listener & U32>:
        r : Result<&1, &1, (U32 & String), Listener> <- TCP.listen(port)
        listen_retry(port, r, rest)

# The echo server: one connection per run, each echoed and closed, and the
# listener handed back every time (the shape lib/wss.bend uses).
law srv_done:
  for l: Listener
  for sent: Socket & Result<&1, &1, (U32 & String), Unit>
  IO(Listener)

def srv_done(l, sent):
  (s2, r) = sent
  do IO<Listener>:
    x : Unit <- TLS.tls_close(s2)
    return l

law srv_echo:
  for l: Listener
  for got: Socket & Result<&1, &1, (U32 & String), List<&2, U32>>
  IO(Listener)

def srv_echo(l, got):
  (s2, r) = got
  match r:
    case Fail{e}:
      do IO<Listener>:
        x : Unit <- TLS.tls_close(s2)
        return l
    case Done{bs}:
      do IO<Listener>:
        sent : Socket & Result<&1, &1, (U32 & String), Unit> <-
          TLS.tls_send_bytes(s2, bs)
        srv_done(l, sent)

law srv_talk:
  for l: Listener
  for sock: Socket
  IO(Listener)

def srv_talk(l, sock):
  do IO<Listener>:
    got : Socket & Result<&1, &1, (U32 & String), List<&2, U32>> <-
      TLS.tls_recv_bytes(sock, PAYLOAD_LEN())
    srv_echo(l, got)

law srv_conn:
  for m: Listener & Result<&1, &1, (U32 & String), Socket>
  IO(Listener)

def srv_conn(m):
  (l2, r) = m
  match r:
    case Fail{e}:
      IO.pure(Listener, l2)
    case Done{sock}:
      srv_talk(l2, sock)

law srv_serve:
  for left: Nat
  for l: Listener
  IO(Unit)

def srv_serve(left, l):
  match left:
    case 0n:
      do IO<Unit>:
        x : Unit <- Listener.close(l)
        return Unit{}
    case 1n+p:
      do IO<Unit>:
        m : Listener & Result<&1, &1, (U32 & String), Socket> <-
          TLS.tls_accept(l, CERT(), KEY())
        l2 : Listener <- srv_conn(m)
        srv_serve(p, l2)

# One client run: connect, send, receive, close; answers 1 when the echo
# came back whole.
law one_done:
  for got: Socket & Result<&1, &1, (U32 & String), List<&2, U32>>
  IO(U32)

def one_done(got):
  (s2, r) = got
  do IO<U32>:
    x : Unit <- TLS.tls_close(s2)
    return score_echo(r)

law one_recv:
  for s: Socket
  IO(U32)

def one_recv(s):
  do IO<U32>:
    got : Socket & Result<&1, &1, (U32 & String), List<&2, U32>> <-
      TLS.tls_recv_bytes(s, PAYLOAD_LEN())
    one_done(got)

law one_sent:
  for sent: Socket & Result<&1, &1, (U32 & String), Unit>
  IO(U32)

def one_sent(sent):
  (s2, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s2)
        return 0
    case Done{u}:
      one_recv(s2)

law one_conn:
  for conn: Result<&1, &1, (U32 & String), Socket>
  IO(U32)

def one_conn(conn):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, (U32 & String), Unit> <-
          TLS.tls_send_bytes(sock, PAYLOAD())
        one_sent(sent)

law one_run:
  for port: U32
  IO(U32)

def one_run(port):
  do IO<U32>:
    conn : Result<&1, &1, (U32 & String), Socket> <-
      TLS.tls_connect_insecure("127.0.0.1", port)
    one_conn(conn)

# Folds one sample into min, max, total ms (the test.bend shape).
def fold_go(+el: Nat, mn: Nat, rest: Nat & Nat) -> Nat & (Nat & Nat):
  match rest:
    case (mx, tot):
      (Nat.min(el, mn), (Nat.max(el, mx), (el + tot : Nat)))

def fold_el(el: Nat, st: Nat & (Nat & Nat)) -> Nat & (Nat & Nat):
  match st:
    case (mn, rest):
      fold_go(el, mn, rest)

law runs_io:
  for fuel: Nat
  for msst: Nat & (Nat & Nat)
  for chk: U32
  for +port: U32
  IO((Nat & (Nat & Nat)) & U32)

def runs_io(fuel, msst, chk, port):
  match fuel:
    case 0n:
      IO.pure((Nat & (Nat & Nat)) & U32, (msst, chk))
    case 1n+f:
      do IO<((Nat & (Nat & Nat)) & U32)>:
        t0 : Nat <- IO.now()
        ok : U32 <- one_run(port)
        t1 : Nat <- IO.now()
        el : Nat = Nat.sub(t1, t0)
        runs_io(f, fold_el(el, msst), (chk + ok : U32), port)

# Prints average with the min/max spread in ms, then the checksum check.
def show_stats_go(name: String, mn: Nat, rest: Nat & Nat) -> IO(Unit):
  match rest:
    case (mx, tot):
      +avg : Nat = Nat.div(tot, BENCH_RUNS())
      IO.print(name ++ " avg=" ++ Nat.show(avg) ++ "ms -"
        ++ Nat.show(Nat.sub(avg, mn)) ++ " +" ++ Nat.show(Nat.sub(mx, avg)))

def show_stats(name: String, st: Nat & (Nat & Nat)) -> IO(Unit):
  match st:
    case (mn, rest):
      show_stats_go(name, mn, rest)

# Message for one check: green with the count, red with both sides.
def check_msg(name: String, got: U32, want: U32, ok: Bool) -> String:
  match ok:
    case True{}:
      name ++ " ok (" ++ U32.show(got) ++ ")"
    case False{}:
      name ++ " FAIL (got " ++ U32.show(got) ++ ", want "
        ++ U32.show(want) ++ ")"

law show_check:
  for name: String
  for +got: U32
  for +want: U32
  IO(Unit)

def show_check(name, got, want):
  IO.print(check_msg(name, got, want, U32.is_eq(got, want)))

law report_all:
  for res: (Nat & (Nat & Nat)) & U32
  IO(Unit)

def report_all(res):
  (msst, chk) = res
  do IO<Unit>:
    show_stats("tls_connect_echo", msst)
    show_check("chk_tls_connect_echo", chk, EXPECTED())

law bench_go:
  for l: Listener
  for port: U32
  IO(Unit)

def bench_go(l, port):
  do IO<Unit>:
    chan : Chan(Unit) <- IO.fork(Unit, srv_serve(BENCH_RUNS(), l))
    res : (Nat & (Nat & Nat)) & U32 <-
      runs_io(BENCH_RUNS(), (RUN_MIN_INIT(), (0n, 0n)), 0, port)
    done : Unit <- IO.join(Unit, chan)
    report_all(res)

law bench_pair:
  for b: Listener & U32
  IO(Unit)

def bench_pair(b):
  (l, port) = b
  bench_go(l, port)

law main:
  IO(Unit)

def main():
  do IO<Unit>:
    b : Listener & U32 <- listen_any(32n, ECHO_PORT())
    bench_pair(b)
