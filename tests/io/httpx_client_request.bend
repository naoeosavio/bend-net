# lib (lib_httpx_client_request): HTTPX.client.request on both ALPN answers
# (TASK-031). H2: one dial, FOUR requests on sids 1, 3, 5, 7 -- one
# client.request each, threading the socket, the sid and the HPACK table
# through the CliSt, so the table the peer inserts into while coding one
# response is what the next response decodes against; a second connection then
# proves the state is per-connection (a fresh CliSt starts at sid 1 again).
# H1: two calls on ONE socket against a single-accept server, where both
# answers on that socket are the only way to score 2 (a re-dial would hang).
# In both the CALLER closes -- client.request never does.
# Golden 7 (4 echoes + 1 solo + 2 H1).
import Base
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX

def httpx_echo(req: HTTPX.Request) -> IO(HTTPX.Response):
  match req:
    case HTTPX.Request{+method, +path, +headers, +body}:
      IO.pure(HTTPX.Response, HTTPX.Response{200, Nil{}, body})

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def score_one(+want: String, r: Result<&1, &1, U32 & String, HTTPX.Response>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      match resp:
        case HTTPX.Response{+status, +headers, +body}:
          b2u(Bool.and(U32.is_eq(status, 200), U32.is_eq(HTTPX.x_eq(body, HTTPX.x_str_bytes(want)), 1)))

def req_of(+want: String) -> HTTPX.Request:
  HTTPX.Request{"POST", "/echo", Nil{}, HTTPX.x_str_bytes(want)}

def close_sum(sock: Socket, +a: U32, +b: U32, +c: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(sock)
    IO.pure(U32, (a + b + c : U32))

# Request 4 of the first connection: scores it and closes (client.request
# never closes on its own).
def h2_req4(got: Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt, +s123: U32) -> IO(U32):
  (sock4, r4, st4) = got
  do IO<U32>:
    +d : U32 = score_one("req-3", r4)
    close_sum(sock4, s123, d, 0)

def h2_req3(got: Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt, +s12: U32, +port: U32) -> IO(U32):
  (sock3, r3, st3) = got
  do IO<U32>:
    +c : U32 = score_one("req-2", r3)
    got4 : Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt <-
      HTTPX.client.request(sock3, st3, "127.0.0.1", port, req_of("req-3"))
    h2_req4(got4, (s12 + c : U32))

def h2_req2(got: Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt, +s1: U32, +port: U32) -> IO(U32):
  (sock2, r2, st2) = got
  do IO<U32>:
    +b : U32 = score_one("req-1", r2)
    got3 : Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt <-
      HTTPX.client.request(sock2, st2, "127.0.0.1", port, req_of("req-2"))
    h2_req3(got3, (s1 + b : U32), port)

# First request of the connection: scores it, then chains the rest (h2_req2
# onward score the answer they receive and issue the next one).
def h2_first(got: Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt, +port: U32) -> IO(U32):
  (sock1, r1, st1) = got
  +a : U32 = score_one("req-0", r1)
  do IO<U32>:
    got2 : Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt <-
      HTTPX.client.request(sock1, st1, "127.0.0.1", port, req_of("req-1"))
    h2_req2(got2, a, port)

def h2_conn(conn: Result<&1, &1, U32 & String, Socket & HTTPX.CliSt>, +port: U32) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock1, st1) = value
      do IO<U32>:
        got1 : Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt <-
          HTTPX.client.request(sock1, st1, "127.0.0.1", port, req_of("req-0"))
        h2_first(got1, port)

# Second connection, one request: the CliSt is per-connection, so this starts
# at sid 1 with an empty table again.
def solo_close(got: Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt, +want: String) ->
  IO(U32):
  (s, r, st) = got
  do IO<U32>:
    +ok : U32 = score_one(want, r)
    x : Unit <- TLS.tls_close(s)
    return ok

def solo_conn(conn: Result<&1, &1, U32 & String, Socket & HTTPX.CliSt>, +port: U32) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, st) = value
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt <-
          HTTPX.client.request(sock, st, "127.0.0.1", port, req_of("req-solo"))
        solo_close(got, "req-solo")

def h2_client(+port: U32) -> IO(U32):
  do IO<U32>:
    c1 : Result<&1, &1, U32 & String, Socket & HTTPX.CliSt> <-
      HTTPX.client.connect_insecure("127.0.0.1", port)
    +a : U32 <- h2_conn(c1, port)
    c2 : Result<&1, &1, U32 & String, Socket & HTTPX.CliSt> <-
      HTTPX.client.connect_insecure("127.0.0.1", port)
    +b : U32 <- solo_conn(c2, port)
    return (a + b : U32)

law h2_side:
  for l: Listener
  IO(U32)

def h2_side(l):
  do IO<U32>:
    x : Unit <- HTTPX.server.concurrent(~httpx_echo, l,
      "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    IO.pure(U32, 0)

law h2_run:
  for b: Listener & U32
  IO(U32)

def h2_run(b):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, h2_side(l))
    h2_client(port)

# H1: server.once_h1 accepts ONE connection, so both answers on one socket are
# the only way to score 2 -- a re-dial would hang.
def h1_end(got: Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt, +sum: U32) -> IO(U32):
  (s2, r2, st2) = got
  +acc : U32 = (sum + score_one("h1-1", r2) : U32)
  do IO<U32>:
    x : Unit <- TLS.tls_close(s2)
    IO.pure(U32, acc)

def h1_step(got: Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt, +port: U32) -> IO(U32):
  (s1, r1, st1) = got
  +a : U32 = score_one("h1-0", r1)
  do IO<U32>:
    got2 : Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt <-
      HTTPX.client.request(s1, st1, "127.0.0.1", port, req_of("h1-1"))
    h1_end(got2, a)

def h1_conn(conn: Result<&1, &1, U32 & String, Socket & HTTPX.CliSt>, +port: U32) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, st) = value
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt <-
          HTTPX.client.request(sock, st, "127.0.0.1", port, req_of("h1-0"))
        h1_step(got, port)

law h1_side:
  for l: Listener
  IO(U32)

def h1_side(l):
  do IO<U32>:
    x : Unit <- HTTPX.server.once_h1(~httpx_echo, l,
      "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    IO.pure(U32, 0)

def h1_client(+port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket & HTTPX.CliSt> <-
      HTTPX.client.connect_insecure("127.0.0.1", port)
    h1_conn(conn, port)

law h1_run:
  for b: Listener & U32
  IO(U32)

def h1_run(b):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, h1_side(l))
    h1_client(port)

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

law main:
  IO(U32)

def main():
  do IO<U32>:
    b1 : Listener & U32 <- listen_any(32n, 18450)
    +h2 : U32 <- h2_run(b1)
    b2 : Listener & U32 <- listen_any(32n, 18451)
    +h1 : U32 <- h1_run(b2)
    +total : U32 = (h2 + h1 : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|7
