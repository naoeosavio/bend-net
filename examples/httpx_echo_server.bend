# HTTPS echo server for node:http2 interop (examples/https_client.js).
# Fixed port so the JS client can dial without a discovery dance.
# Listens 127.0.0.1:19893, echoes request bodies; prints DONE after
# the first connection's streams finish and exits (manual only —
# not in check.sh).
#   bend examples/httpx_echo_server.bend
import Base
import ../lib/httpx.bend as HTTPX

def h2_echo(req: HTTPX.Request) -> IO(HTTPX.Response):
  match req:
    case HTTPX.Request{+method, +path, +headers, +body}:
      do IO<HTTPX.Response>:
        x : Unit <- IO.print("SRV got " ++ U32.show(U32.from_nat(HTTPX.x_len(body))))
        IO.pure(HTTPX.Response, HTTPX.Response{200, Nil{}, body})

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTPX.server.on(~h2_echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    return "up"

def after_listen(r: Result<&1, &1, U32 & String, Listener>) -> IO(Unit):
  match r:
    case Fail{e}:
      IO.die(Unit, 1, "listen failed")
    case Done{l}:
      do IO<Unit>:
        chan : Chan(String) <- IO.fork(String, server_side(l))
        # Wait for the server fiber: returns when the peer closes
        # (same join pattern as tests/io/httpx_fetch_https.bend).
        s : String <- IO.join(String, chan)
        z : Unit <- IO.print("DONE 1/1")
        IO.die(Unit, 0, "")

def main() -> IO(Unit):
  do IO<Unit>:
    r : Result<&1, &1, U32 & String, Listener> <- TCP.listen(19893)
    after_listen(r)
