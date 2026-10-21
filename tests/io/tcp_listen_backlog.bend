# lib (tcp_listen_backlog): the explicit accept-queue depth from
# lib/tcp.bend. Base's TCP.listen fixes the queue at 16, so a burst of
# more dials than that makes the kernel drop the excess SYNs and every
# dropped dial waits out the TCP retry (~1s, measured in TASK-041):
# scenario A drives 20 simultaneous TLS+H2 clients through
# TCP.listen_backlog and scores one per echo, failing when the burst
# takes longer than BURST_BUDGET_MS. Measured on this machine, interp:
# 234 ms through the deep listener against 1129 ms through Base's 16.
# Scenario B checks the fail-closed paths: backlog 0 is EINVAL (22) and
# a port already bound is EADDRINUSE (98). Golden 20.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX
import ../../lib/http.bend as HTTP

def CLIENTS() -> Nat:
  20n

# Interp: 234 ms healthy, 1129 ms on a 16-deep queue (the TCP retry is
# ~1s on its own), so the budget sits between the two with margin.
def BURST_BUDGET_MS() -> U32:
  700

def EINVAL() -> U32:
  22

def EADDRINUSE() -> U32:
  98

def WANT_FAIL_PATHS() -> U32:
  2

def h2_echo(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, body})

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def score(r: Result<&1, &1, U32 & String, String>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{body}:
      b2u(String.eq(body, "hello"))

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTPX.server.on(~h2_echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    return "up"

law client:
  for port: U32
  IO(U32)

def client(port):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, String> <- HTTPX.request_insecure("127.0.0.1", port, "/echo", "POST", Nil{}, "hello")
    IO.pure(U32, score(r))

law burst:
  for port: U32
  for n: Nat
  IO(U32)

def burst(port, n):
  match n:
    case 0n:
      IO.pure(U32, 0)
    case 1n+t:
      +p = port
      do IO<U32>:
        chan : Chan(U32) <- IO.fork(U32, client(p))
        rest : U32 <- burst(p, t)
        a : U32 <- IO.join(U32, chan)
        IO.pure(U32, (a + rest : U32))

law within_budget:
  for ok: Bool
  for score: U32
  IO(U32)

def within_budget(ok, score):
  match ok:
    case True{}:
      IO.pure(U32, score)
    case False{}:
      IO.die(U32, 1, "burst exceeded the accept-queue budget")

law timed_burst:
  for port: U32
  IO(U32)

def timed_burst(port):
  do IO<U32>:
    t0 : Nat <- IO.now()
    score2 : U32 <- burst(port, CLIENTS())
    t1 : Nat <- IO.now()
    spent : U32 <- IO.pure(U32, U32.from_nat(Nat.sub(t1, t0)))
    within_budget(U32.is_le(spent, BURST_BUDGET_MS()), score2)

law code_score:
  for e: U32 & String
  for want: U32
  U32

def code_score(e, want):
  (code, message) = e
  b2u(U32.is_eq(code, want))

law score_fail:
  for r: Result<&1, &1, U32 & String, Listener>
  for want: U32
  U32

def score_fail(r, want):
  match r:
    case Fail{e}:
      code_score(e, want)
    case Done{l}:
      0

law fail_paths:
  for port: U32
  IO(U32)

def fail_paths(port):
  +p = port
  +b = TCP.LISTEN_BACKLOG()
  do IO<U32>:
    r0 : Result<&1, &1, U32 & String, Listener> <- TCP.listen_backlog(p, 0)
    s0 : U32 <- IO.pure(U32, score_fail(r0, EINVAL()))
    r1 : Result<&1, &1, U32 & String, Listener> <- TCP.listen_backlog(p, b)
    s1 : U32 <- IO.pure(U32, score_fail(r1, EADDRINUSE()))
    IO.pure(U32, (s0 + s1 : U32))

law want_fail_paths:
  for ok: Bool
  for score: U32
  IO(U32)

def want_fail_paths(ok, score):
  match ok:
    case True{}:
      IO.pure(U32, score)
    case False{}:
      IO.die(U32, 1, "fail-closed paths changed")

law check_fail_paths:
  for got: U32
  for score: U32
  IO(U32)

def check_fail_paths(got, score):
  want_fail_paths(U32.is_eq(got, WANT_FAIL_PATHS()), score)

law listen_deep:
  for port: U32
  IO(Result<&1, &1, U32 & String, Listener>)

def listen_deep(port):
  TCP.listen_backlog(port, TCP.LISTEN_BACKLOG())

law listen_retry:
  for port: U32
  for r: Result<&1, &1, U32 & String, Listener>
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
        r : Result<&1, &1, U32 & String, Listener> <- listen_deep(port)
        listen_retry(port, r, rest)

law main_go:
  for b: Listener & U32
  IO(U32)

def main_go(b):
  (l, port) = b
  +p = port
  do IO<U32>:
    fails : U32 <- fail_paths(p)
    chan : Chan(String) <- IO.fork(String, server_side(l))
    score2 : U32 <- timed_burst(p)
    ok : U32 <- check_fail_paths(fails, score2)
    +shown : U32 = ok
    w : Unit <- IO.print(U32.show(shown))
    z : Unit <- IO.die(Unit, 0, "")
    return shown

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 18480)
    main_go(b)

#|20
