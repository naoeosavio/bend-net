# Phase 0 gate probe: the TLS bridge candidates measured inside a real
# effect, against a loopback TLS server (self-signed, the shape
# tests/io/tls_connect_close.bend already uses), so the gate needs no
# network. Mode 0 parks on a 1 ms deadline (cooperative, io_park_on) and
# mode 1 blocks the main thread on Atomics.wait; each mode runs beside
# its own ticker, which prints how long its 1 ms sleep really took -- a
# tick far past 1 ms means the loop was held.
#
# The effect under probe is the scratch twin; the server is the current
# lib TLS server, which the later phases replace.
import Base
import ../../../lib/tls.bend as TLS

# The scratch bridge twin: TLS in a worker that dials its own socket.
def p0_tls(ip: String, sni: String, port: U32, mode: U32, req: String) ->
  IO(U32):
  import "./effs/p0_tls.js"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

def ECHO_PORT() -> U32:
  19991

def ECHO_MAX() -> U32:
  4096

# Milliseconds the server waits before accepting: it makes the op long
# enough for the ticker to expose a bridge that holds the loop.
def SRV_DELAY_MS() -> U32:
  150

def TICKS() -> Nat:
  400n

def TICK_MS() -> U32:
  1

# Listener, retrying the port when it is taken (the shape of the TLS
# golden test: a fixed port keeps the server reachable by the client).
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

# One ticker tick per millisecond, printed as the milliseconds the sleep
# actually took.
law tick:
  for n: Nat
  IO(Unit)

def tick(n):
  match n:
    case 0n:
      IO.pure(Unit, Unit{})
    case 1n+p:
      do IO<Unit>:
        t0 : Nat <- IO.now()
        w : Unit <- IO.sleep(TICK_MS())
        at : Nat <- IO.now()
        t : Unit <- IO.print("t" ++ Nat.show(Nat.sub(at, t0)))
        tick(p)

# The echo server: reads at most ECHO_MAX bytes and sends them back.
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
      TLS.tls_recv_bytes(sock, ECHO_MAX())
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

# Serves `left` connections and hands the listener back every time, the
# shape lib/wss.bend uses for its accept loop.
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
        w : Unit <- IO.sleep(SRV_DELAY_MS())
        m : Listener & Result<&1, &1, (U32 & String), Socket> <-
          TLS.tls_accept_http1(l, CERT(), KEY())
        l2 : Listener <- srv_conn(m)
        srv_serve(p, l2)

# Mode 0 (cooperative park) unless P0_MODE is set, which selects mode 1
# (Atomics.wait) so the gate can prove that one blocks the loop.
def mode_of(r: Result<&1, &1, (U32 & String), String>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{s}:
      1

law pick_mode:
  IO(U32)

def pick_mode():
  do IO<U32>:
    r : Result<&1, &1, (U32 & String), String> <- IO.get_env("P0_MODE")
    IO.pure(U32, mode_of(r))

# Runs one mode beside a ticker; the marker line closes the window the
# gate reads the tick overshoot from.
law probe_mode:
  for +mode: U32
  for +ip: String
  for port: U32
  IO(U32)

def probe_mode(mode, ip, port):
  do IO<U32>:
    s : Unit <- IO.spawn(Unit, tick(TICKS()))
    +ms : U32 <- p0_tls(ip, "localhost", port, mode, "hello")
    m : Unit <- IO.print("|mode" ++ U32.show(mode) ++ " " ++ U32.show(ms))
    return ms

law main_go:
  for l: Listener
  for +port: U32
  IO(U32)

def main_go(l, port):
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, srv_serve(1n, l))
    +mode : U32 <- pick_mode()
    +ms : U32 <- probe_mode(mode, "127.0.0.1", port)
    done : Unit <- IO.join(Unit, chan)
    return ms

law main_pair:
  for b: Listener & U32
  IO(U32)

def main_pair(b):
  (l, port) = b
  main_go(l, port)

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, ECHO_PORT())
    main_pair(b)
