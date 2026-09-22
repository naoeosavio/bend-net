# lib (lib_https_streams): two sequential streams on one HTTPS
# connection. The server serves via HTTPS.serve_start (multi-stream
# sequential loop); the client connects once and POSTs body1 on sid 1
# then body2 on sid 3 over the same TLS connection, checking both
# echoes and statuses. Golden 1.
import Base
import ../../lib/tls.bend as TLS
import ../../lib/https.bend as HTTPS
import ../../lib/http2.bend as H2

def body1() -> List<&2, U32>:
  [104, 101, 108, 108, 111]

def body2() -> List<&2, U32>:
  [119, 111, 114, 108, 100, 33]

def h2_echo(req: H2.H2Request) -> IO(H2.H2Response):
  match req:
    case H2.H2Request{+method, +path, +headers, +body}:
      IO.pure(H2.H2Response, H2.H2Response{200, Nil{}, body})

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def mul_eq(+acc: U32, same: Bool) -> U32:
  match same:
    case True{}:
      acc
    case False{}:
      0

def bytes_eq(a: List<&2, U32>, b: List<&2, U32>) -> U32:
  match a b:
    case Nil{} Nil{}:
      1
    case h1 <> t1 h2 <> t2:
      mul_eq(bytes_eq(t1, t2), U32.is_eq(h1, h2))
    case _ _:
      0

law server_down:
  for l: Listener
  for e: U32 & String
  IO(String)

def server_down(l, e):
  do IO<String>:
    x : Unit <- Listener.close(l)
    return "down"

def server_close(l: Listener) -> IO(String):
  do IO<String>:
    y : Unit <- Listener.close(l)
    return "up"

def server_served(l: Listener, sock: Socket) -> IO(String):
  do IO<String>:
    x : Unit <- HTTPS.serve_start(~h2_echo, sock, 8n)
    server_close(l)

def server_conn(m: Listener & Result<&1, &1, (U32 & String), Socket>) -> IO(String):
  (l, r) = m
  match r:
    case Fail{e}:
      server_down(l, e)
    case Done{sock}:
      server_served(l, sock)

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    m : Listener & Result<&1, &1, (U32 & String), Socket> <- TLS.tls_accept(l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    server_conn(m)

def client_score2(sock: Socket, body: List<&2, U32>, st_ok: U32, acc: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(sock)
    +eq : U32 = bytes_eq(body, body2())
    return (st_ok * eq * acc : U32)

def client_done2(acc: U32, got: Socket & Result<&1, &1, (U32 & String), H2.H2Response>) -> IO(U32):
  (s2, r) = got
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s2)
        return 0
    case Done{+resp}:
      match resp:
        case H2.H2Response{+status, +headers, +body}:
          client_score2(s2, body, b2u(U32.is_eq(status, 200)), acc)

def client_second(acc: U32, got: Socket & Result<&1, &1, (U32 & String), H2.H2Response>) -> IO(U32):
  (s2, r) = got
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s2)
        return 0
    case Done{+resp}:
      match resp:
        case H2.H2Response{+status, +headers, +body}:
          do IO<U32>:
            +ok1 : U32 = (b2u(U32.is_eq(status, 200)) * bytes_eq(body, body1()) : U32)
            got2 : Socket & Result<&1, &1, (U32 & String), H2.H2Response> <- H2.h2_request(s2, 3, "POST", "/echo", Nil{}, body2())
            client_done2((acc * ok1 : U32), got2)

def client_conn(conn: Result<&1, &1, (U32 & String), Socket>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        got : Socket & Result<&1, &1, (U32 & String), H2.H2Response> <- H2.h2_request(sock, 1, "POST", "/echo", Nil{}, body1())
        client_second(1, got)

law client:
  for port: U32
  IO(U32)

def client(port):
  do IO<U32>:
    conn : Result<&1, &1, (U32 & String), Socket> <- H2.h2_connect_insecure("127.0.0.1", port)
    client_conn(conn)

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

law main_go:
  for b: Listener & U32
  IO(U32)

def main_go(b):
  (l, port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    +a : U32 <- client(port)
    s : String <- IO.join(String, chan)
    +total : U32 = (a : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 18440)
    main_go(b)

#|1
