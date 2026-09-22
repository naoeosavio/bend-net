# HTTPS echo server for node:http2 interop (examples/https_client.js).
# Fixed port so the JS client can dial without a discovery dance.
# Listens 127.0.0.1:19893, echoes request bodies; prints DONE after
# the first connection's streams finish and exits (manual only —
# not in check.sh).
#   bend examples/https_echo_server.bend
import Base
import ../lib/https.bend as HTTPS
import ../lib/http2.bend as H2

def h2_echo(req: H2.H2Request) -> IO(H2.H2Response):
  match req:
    case H2.H2Request{+method, +path, +headers, +body}:
      IO.pure(H2.H2Response, H2.H2Response{200, Nil{}, body})

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTPS.server_on(~h2_echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem", 8n)
    return "up"

def after_listen(r: Result<&1, &1, U32 & String, Listener>) -> IO(Unit):
  match r:
    case Fail{e}:
      IO.die(Unit, 1, "listen failed")
    case Done{l}:
      do IO<Unit>:
        chan : Chan(String) <- IO.fork(String, server_side(l))
        # Wait for the server fiber: returns when the peer closes
        # (same join pattern as tests/io/https_fetch.bend).
        s : String <- IO.join(String, chan)
        z : Unit <- IO.print("DONE 1/1")
        IO.die(Unit, 0, "")

def main() -> IO(Unit):
  do IO<Unit>:
    r : Result<&1, &1, U32 & String, Listener> <- TCP.listen(19893)
    after_listen(r)
