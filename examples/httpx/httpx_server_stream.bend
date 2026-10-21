# HTTPX streaming-upload server for node interop (manual only — not in check.sh).
# Serves HTTPX.server.stream forever on an ephemeral port (printed to
# stdout for the peer script). The pure handler caps one chunk at 3 bytes:
# Head asks for more, an over-cap chunk answers early 413, a small final
# chunk echoes 200. Mirrors tests/io/httpx_server_stream.bend without its
# loopback client or golden.
# Usage: bend examples/httpx/httpx_server_stream.bend -o /tmp/opencode/httpx_server_stream
#        /tmp/opencode/httpx_server_stream   # prints PORT, serves until killed
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX
import ../../lib/http.bend as HTTP

def cap() -> U32:
  3

def over_cap(+chunk: List<&2, U32>) -> Bool:
  U32.is_gt(U32.from_nat(HTTP.x_len(chunk)), cap())

def h_data_go(is_over: Bool, +chunk: List<&2, U32>) -> HTTP.SrvOut:
  match is_over:
    case True{}:
      HTTP.RespondEarly{HTTP.Response{413, Nil{}, Nil{}}}
    case False{}:
      HTTP.RespondEarly{HTTP.Response{200, Nil{}, chunk}}

def h(ev: HTTP.SrvEv) -> HTTP.SrvOut:
  match ev:
    case HTTP.SrvReqHead{slot, head}:
      HTTP.Continue{}
    case HTTP.SrvReqData{slot, +chunk, fin}:
      h_data_go(over_cap(chunk), chunk)

law server:
  for l: Listener
  IO(Unit)

def server(l):
  HTTPX.server.stream(~h, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")

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

# Base's TCP.listen fixes the accept queue at 16, so a burst of more
# dials than that makes the kernel drop the excess SYNs and every dropped
# dial waits out the TCP retry (~1s, measured in TASK-041). This server
# is dialed by peers that can arrive together, so it listens with the
# package's depth instead.
law listen_deep:
  for port: U32
  IO(Result<&1, &1, (U32 & String), Listener>)

def listen_deep(port):
  TCP.listen_backlog(port, TCP.LISTEN_BACKLOG())

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
        r : Result<&1, &1, (U32 & String), Listener> <- listen_deep(port)
        listen_retry(port, r, rest)

law main_go:
  for b: Listener & U32
  IO(Unit)

def main_go(b):
  (l, port) = b
  do IO<Unit>:
    w : Unit <- IO.print(U32.show(port))
    server(l)

law main:
  IO(Unit)

def main():
  do IO<Unit>:
    b : Listener & U32 <- listen_any(32n, 19895)
    main_go(b)
