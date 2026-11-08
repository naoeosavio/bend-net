# io (http2_pre_eof): a peer that completes the TLS handshake and closes
# without sending the client preface must not stall the server.
#
# Found by h2spec (task-070 phase 1): `spec.ServerDataLength` leaves one
# connection open, and several cases close a connection right after the
# handshake. The preface loop read the empty list that TLS answers at the
# end of the stream and asked for more bytes forever. The spin starved the
# accept loop, so the next TLS dial timed out.
#
# The test runs the real concurrent server, closes one silent connection,
# and then asks a second connection for "/". Score 1 when the answer is
# 200, golden 1.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18650

def TRIES() -> Nat:
  32n

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

def HOST() -> String:
  "127.0.0.1"

def ok(req: HTTP.Request) -> IO(HTTP.Response):
  IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, Nil{}})

def weigh(is_ok: Bool, +weight: U32) -> U32:
  match is_ok:
    case True{}:
      weight
    case False{}:
      0

def req() -> HTTP.Request:
  HTTP.Request{"GET", "/", Nil{}, Nil{}}

def resp_ok(r: Result<&1, &1, U32 & String, HTTP.Response>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{resp}:
      match resp:
        case HTTP.Response{+status, +headers, +body}:
          weigh(U32.is_eq(status, 200), 1)

def silent(sock: Socket) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(sock)
    IO.pure(U32, 0)

def quiet_go(r: Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      silent(sock)

# The silent peer: handshake with ALPN h2, then close with no preface.
def quiet(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_insecure(HOST(), port)
    quiet_go(r)

def client(+port: U32) -> IO(U32):
  do IO<U32>:
    +q : U32 <- quiet(port)
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTP2.client.once_insecure(HOST(), port, req())
    +s : U32 = resp_ok(r)
    IO.pure(U32, (q + s : U32))

def server_side(l: Listener) -> IO(Unit):
  do IO<Unit>:
    x : Unit <- HTTP2.server.concurrent(~ok, l, CERT(), KEY())
    IO.pure(Unit, Unit{})

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

def main_go(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(Unit) <- IO.fork(Unit, server_side(l))
    +total : U32 <- client(port)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(TRIES(), PORT())
    main_go(b)

#|1
