# lib (lib_https_server_on): the generic keep-alive HTTPS server.
# server_on accepts on a TLS listener with IO.spawn per connection and
# serves n sequential streams per connection (like HTTP.server_on but
# over HTTP/2). Two clients connect one after the other, each POSTing
# "hello"; both must echo. Golden 1.
import Base
import ../../lib/tls.bend as TLS
import ../../lib/https.bend as HTTPS
import ../../lib/http2.bend as H2

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

def client_two(r1: U32, r2: U32) -> U32:
  (r1 * r2 : U32)

def client_score(r: Result<&1, &1, (U32 & String), String>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+body}:
      match body:
        case SCon{Chr{104}, SCon{Chr{101}, SCon{Chr{108}, SCon{Chr{108}, SCon{Chr{111}, SNil{}}}}}}:
          1
        case SCon{Chr{119}, SCon{Chr{111}, SCon{Chr{114}, SCon{Chr{108}, SCon{Chr{100}, _}}}}}:
          1
        case _:
          0

law client:
  for +port: U32
  IO(U32)

def client(port):
  do IO<U32>:
    r1 : Result<&1, &1, (U32 & String), String> <- HTTPS.send_request_insecure("127.0.0.1", port, "/echo", "POST", Nil{}, "hello")
    r2 : Result<&1, &1, (U32 & String), String> <- HTTPS.send_request_insecure("127.0.0.1", port, "/echo", "POST", Nil{}, "world")
    IO.pure(U32, (client_score(r1) * client_score(r2) : U32))

def listen_retry(port: U32, r: Result<&1, &1, (U32 & String), Listener>, rest: IO(Listener & U32)) -> IO(Listener & U32):
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

def main_go(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    +a : U32 <- client(port)
    +total : U32 = (a : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 18440)
    main_go(b)

#|1
