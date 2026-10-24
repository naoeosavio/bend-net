# io (httpx_h2_server_stream_lanes): the three server lanes of the H2
# stream form (task-059 phase 3). Three listeners, one lane for each:
#   - server.stream.on: two connections, two streams in order on each.
#     The order is kept inside a connection.
#   - server.stream.once: one accept, one connection, two streams in
#     order.
#   - server.stream.concurrent: two streams in flight on one connection.
# Every point is a 200 answer that echoes the two-byte body, so the order
# of the requests is not part of the score; the answer is.
#
# Score: on +4, once +2, concurrent +2, golden 8.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def hi_bytes() -> List<&2, U32>:
  HTTP.x_str_bytes("hi")

def echo_req() -> HTTP.Request:
  HTTP.Request{"POST", "/echo", Nil{}, hi_bytes()}

# Server handler: Continue on the head, echo 200 on the data.
def h(ev: HTTP.SrvEv) -> HTTP.SrvOut:
  match ev:
    case HTTP.SrvReqHead{slot, head}:
      HTTP.Continue{}
    case HTTP.SrvReqData{slot, +chunk, fin}:
      HTTP.RespondEarly{HTTP.Response{200, Nil{}, chunk}}

def score(r: Result<&1, &1, U32 & String, HTTP.Response>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      match resp:
        case HTTP.Response{+status, +headers, +body}:
          b2u(Bool.and(U32.is_eq(status, 200), U32.is_eq(HTTP.x_eq(body, hi_bytes()), 1)))

# The second answer of the connection: score it, then close.
def conn_c(got: Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt, +acc: U32) -> IO(U32):
  (sock, r, st) = got
  do IO<U32>:
    +a : U32 = (acc + score(r) : U32)
    x : Unit <- TLS.tls_close(sock)
    IO.pure(U32, a)

# The second request of the connection, over the same state.
def conn_b(got: Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt, +port: U32, +acc: U32) -> IO(U32):
  (sock, r, st) = got
  do IO<U32>:
    +a : U32 = (acc + score(r) : U32)
    g2 : Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt <- HTTP2.client.request(sock, st, HOST(), port, echo_req())
    conn_c(g2, a)

def conn_a(conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>, +port: U32, +acc: U32) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, acc)
    case Done{value}:
      (sock, st) = value
      do IO<U32>:
        g1 : Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt <- HTTP2.client.request(sock, st, HOST(), port, echo_req())
        conn_b(g1, port, acc)

# N connections, two streams in order on each.
def conns(n: Nat, +port: U32, +acc: U32) -> IO(U32):
  match n:
    case 0n:
      IO.pure(U32, acc)
    case 1n+t:
      do IO<U32>:
        conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTP2.client.connect_insecure(HOST(), port)
        a2 : U32 <- conn_a(conn, port, acc)
        conns(t, port, a2)

# The weight of one answer of the concurrent lane.
def w(resp: HTTP.Response) -> U32:
  match resp:
    case HTTP.Response{status, headers, body}:
      b2u(U32.is_eq(status, 200))

def conc_done(r: Result<&1, &1, U32 & String, U32>) -> IO(U32):
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{+n}:
      IO.pure(U32, n)

def client_conc(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32> <- HTTP2.client.concurrent_insecure(~w, HOST(), port, [echo_req(), echo_req()])
    conc_done(r)

law server_on:
  for l: Listener
  IO(String)

def server_on(l):
  do IO<String>:
    x : Unit <- HTTP2.server.stream.on(~h, l, CERT(), KEY())
    return "up"

law server_once:
  for l: Listener
  IO(String)

def server_once(l):
  do IO<String>:
    x : Unit <- HTTP2.server.stream.once(~h, l, CERT(), KEY())
    return "up"

law server_conc:
  for l: Listener
  IO(String)

def server_conc(l):
  do IO<String>:
    x : Unit <- HTTP2.server.stream.concurrent(~h, l, CERT(), KEY())
    return "up"

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
  for b2: Listener & U32
  for b3: Listener & U32
  IO(U32)

def main_go(b, b2, b3):
  (l1, port1) = b
  (l2, port2) = b2
  (l3, port3) = b3
  do IO<U32>:
    c1 : Chan(String) <- IO.fork(String, server_on(l1))
    c2 : Chan(String) <- IO.fork(String, server_once(l2))
    c3 : Chan(String) <- IO.fork(String, server_conc(l3))
    +s1 : U32 <- conns(2n, port1, 0)
    +s2 : U32 <- conns(1n, port2, 0)
    +s3 : U32 <- client_conc(port3)
    +total : U32 = (s1 + s2 + s3 : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 18700)
    b2 : Listener & U32 <- listen_any(32n, 18710)
    b3 : Listener & U32 <- listen_any(32n, 18720)
    x : U32 <- main_go(b, b2, b3)
    return x

#|8
