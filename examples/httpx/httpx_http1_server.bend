# Dual H2+H1 TLS server on one port (ALPN), manual interop driver.
# HTTPX.server.on_alpn dispatches ALPN internally and feeds BOTH lanes into the
# SAME handler, so there is no second H1 handler here: httpx's H1 and H2 share
# the Request/Response record (the old pair -- h2_echo plus an h1_echo taking
# method/path/headers/body separately -- is what TASK-026 collapsed).
# Listens 127.0.0.1:19895 with the test PEMs; echoes request bodies.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX

def httpx_echo(request: HTTPX.Request) -> IO(HTTPX.Response):
  match request:
    case HTTPX.Request{method, path, headers, body}:
      IO.pure(HTTPX.Response, HTTPX.Response{200, Nil{}, body})

def serve(listener: Listener) -> IO(Unit):
  do IO<Unit>:
    result : Unit <- HTTPX.server.on_alpn(~httpx_echo, listener,
      "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    return result

def main_result(
  result: Result<&1, &1, (U32 & String), Listener>) -> IO(Unit):
  match result:
    case Fail{e}:
      IO.die(Unit, 1, "listen failed")
    case Done{listener}:
      do IO<Unit>:
        output : Unit <- IO.print("LISTEN 19895")
        serve(listener)

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

def main() -> IO(Unit):
  do IO<Unit>:
    result : Result<&1, &1, (U32 & String), Listener> <- listen_deep(19895)
    main_result(result)