# httpx (lib_httpx_h1_keepalive): H1 keep-alive, phases 1-3.
#
# Phase 1 — the pure close policy. x_h1.conn_close is the H1 server's only
# closure signal: HTTP/1.1 keeps the connection alive unless the request
# carries "connection: close", matched case-insensitively on name and
# value (x_h1.eq_ci). A missing header never closes and "keep-alive" never
# closes. Two vectors run the real head parser first, because
# x_h1.forbidden filters the RENDER side only: a peer's
# "connection: close" must survive parse_hs into the Request headers or
# the policy would be dead code. All 10 vectors score 1.
#
# Phase 2 — the reuse proof, four scenarios. A) server.once_h1 accepts
# ONE connection and the client sends three POSTs over that same TLS
# socket with x_h1.exch.send (the exchange that does not close): 3 can
# only come out if all three were answered on the one connection, since
# a one-shot server would close after the first and the next send/read
# would fail. B) the opposite end: server.on_h1 with the one-shot client
# still answers exactly 1 and keeps accepting. C) a raw request carrying
# "connection: close" (render_req can never emit it) must be answered 200
# and then the server must really close — the next read sees EOF. D) the
# plaintext mirror, the same three-on-one-connection shape through
# x_h1p, because x_h1p.srv is a copy and needs its own proof. E) the same
# batch through the unified client API: client.on_insecure dials once,
# client.on.batch_st takes the is_h2=False branch into the new H1
# sequential lane (it used to close with Fail 615) and the three requests
# ride that one socket against a single-accept server. F) the keep-alive
# single-request entry (client.request) on an H1 CliSt: two calls on the
# same socket, in order — before Phase 3 it wrote H2 frames onto the
# HTTP/1.1 socket.
# Golden 14 = 1 (vectors) + 3 (reuse) + 1 (one-shot) + 1 (close) + 3
# (plaintext reuse) + 3 (client-API batch) + 2 (client.request).
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def bool_eq(a: Bool, b: Bool) -> Bool:
  match a b:
    case True{} True{}:
      True{}
    case False{} False{}:
      True{}
    case _ _:
      False{}

# close_want(hs, want): 1 iff conn_close(hs) matches the expected verdict.
def close_want(hs: List<&2, HTTPX.Hdr>, want: Bool) -> U32:
  b2u(bool_eq(HTTPX.x_h1.conn_close(hs), want))

def hdr(n: String, v: String) -> HTTPX.Hdr:
  HTTPX.Hdr{n, v}

def h1(n: String, v: String) -> List<&2, HTTPX.Hdr>:
  hdr(n, v) <> Nil{}

# no Connection header at all: HTTP/1.1 default is keep-alive.
def v1() -> U32:
  close_want(Nil{}, False{})

def v2() -> U32:
  close_want(h1("connection", "close"), True{})

# value side is case-insensitive ("Close" means close).
def v3() -> U32:
  close_want(h1("connection", "Close"), True{})

# name side is case-insensitive ("Connection" means connection).
def v4() -> U32:
  close_want(h1("Connection", "close"), True{})

def v5() -> U32:
  close_want(h1("connection", "keep-alive"), False{})

# "close" on another header name is not the signal.
def v6() -> U32:
  close_want(h1("x-close", "close"), False{})

# close amidst other headers, not first.
def v7() -> U32:
  close_want(hdr("host", "example.com") <> h1("connection", "close"),
    True{})

# contradictory repeats: any "close" wins (the fold is an OR).
def v8() -> U32:
  close_want(hdr("connection", "keep-alive") <> h1("connection", "close"),
    True{})

# Raw head bytes -> the server's own head chain -> parsed List<Hdr>.
def parse_head(raw: String) ->
  Result<&1, &1, U32 & String, List<&2, HTTPX.Hdr>>:
  +head = HTTPX.x_h1.split_head(HTTPX.x_h1.split(HTTPX.x_str_bytes(raw)))
  HTTPX.x_h1.parse_hs(HTTPX.x_h1.rest_lines(HTTPX.x_h1.head_lines(head)))

def raw_close_go(r: Result<&1, &1, U32 & String, List<&2, HTTPX.Hdr>>, want: Bool) ->
  U32:
  match r:
    case Fail{e}:
      0
    case Done{+hs}:
      close_want(hs, want)

def raw_want(raw: String, want: Bool) -> U32:
  raw_close_go(parse_head(raw), want)

# the parsed header list still carries "connection: close" -> close.
def v9() -> U32:
  raw_want("GET / HTTP/1.1\r\nConnection: close\r\n\r\n", True{})

# the parser does not invent the header when the peer omits it -> keep.
def v10() -> U32:
  raw_want("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", False{})

def vectors() -> U32:
  +a : U32 = (v1() + v2() + v3() + v4() + v5() : U32)
  +b : U32 = (v6() + v7() + v8() + v9() + v10() : U32)
  b2u(U32.is_eq((a + b : U32), 10))

# Phase 2: the batch over one connection.
# ---------------------------------------------------------------------

def echo(req: HTTPX.Request) -> IO(HTTPX.Response):
  match req:
    case HTTPX.Request{method, path, headers, body}:
      IO.pure(HTTPX.Response, HTTPX.Response{200, Nil{}, body})

def score_echo(+want: String, r: Result<&1, &1, U32 & String, HTTPX.Response>) ->
  U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      match resp:
        case HTTPX.Response{+status, +headers, +body}:
          b2u(Bool.and(U32.is_eq(status, 200),
            U32.is_eq(HTTPX.x_eq(body, HTTPX.x_str_bytes(want)), 1)))

def req_bytes(+port: U32, +body: String) ->
  Result<&1, &1, U32 & String, List<&2, U32>>:
  HTTPX.x_h1.render_req("POST", "/echo", "127.0.0.1", port, Nil{},
    HTTPX.x_str_bytes(body))

# One step of the sequential batch: score the response just read, then
# either send the next request down the SAME socket (rest non-empty) or
# close it once the last one scored. Never reconnects — that is the
# point of the golden. The step is split in three because this dialect
# wants a match to head a def body (or follow only a destructuring), and
# wants the score binding before the effect, not before a match.
def batch_end(got: Socket & Result<&1, &1, U32 & String, HTTPX.Response>, +want: String, +sum: U32) ->
  IO(U32):
  (sock, r) = got
  +acc : U32 = (sum + score_echo(want, r) : U32)
  do IO<U32>:
    x : Unit <- TLS.tls_close(sock)
    IO.pure(U32, acc)

@unsafe
def batch_next(got: Socket & Result<&1, &1, U32 & String, HTTPX.Response>, +port: U32, +want: String, +next: String, +more: List<String>, +sum: U32) ->
  IO(U32):
  (sock, r) = got
  +acc : U32 = (sum + score_echo(want, r) : U32)
  do IO<U32>:
    out : Socket & Result<&1, &1, U32 & String, HTTPX.Response> <-
      HTTPX.x_h1.exch.send(sock, req_bytes(port, next), "POST")
    batch_step(out, port, next, more, acc)

@unsafe
def batch_step(got: Socket & Result<&1, &1, U32 & String, HTTPX.Response>, +port: U32, +want: String, rest: List<String>, +sum: U32) ->
  IO(U32):
  match rest:
    case Nil{}:
      batch_end(got, want, sum)
    case next <> more:
      batch_next(got, port, want, next, more, sum)

def batch_run(conn: Result<&1, &1, U32 & String, Socket>, +port: U32) ->
  IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        out : Socket & Result<&1, &1, U32 & String, HTTPX.Response> <-
          HTTPX.x_h1.exch.send(sock, req_bytes(port, "hello-0"), "POST")
        batch_step(out, port, "hello-0", ["hello-1", "hello-2"], 0)

def batch_side(l: Listener) -> IO(U32):
  do IO<U32>:
    x : Unit <- HTTPX.server.once_h1(~echo, l,
      "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    IO.pure(U32, 0)

def run_batch(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, batch_side(l))
    conn : Result<&1, &1, U32 & String, Socket> <-
      TLS.tls_connect_noalpn_insecure("127.0.0.1", port)
    batch_run(conn, port)

# The one-shot end: server.on_h1 (recursive accept) with the client that
# closes after one request must still answer exactly 1.
def once_client(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTPX.Response> <-
      HTTPX.client.once_insecure("127.0.0.1", port,
        HTTPX.Request{"POST", "/echo", Nil{}, HTTPX.x_str_bytes("hello")})
    IO.pure(U32, score_echo("hello", r))

def once_side(l: Listener) -> IO(U32):
  do IO<U32>:
    x : Unit <- HTTPX.server.on_h1(~echo, l,
      "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    IO.pure(U32, 0)

def run_once(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, once_side(l))
    once_client(port)

# Scenario C: the peer asks for close. render_req can never emit the
# header (x_h1.forbidden skips it on the way out), so this writes the
# raw request and reads the answer with the same response reader the H1
# client uses. 1 iff the answer is 200 AND the server really closed: a
# second read must see an empty recv (EOF) — not another answer and not
# a hang. That is the keep=False edge of x_h1.conn_close.
def close_raw(+port: U32) -> List<&2, U32>:
  HTTPX.x_str_bytes("GET /echo HTTP/1.1\r\nHost: 127.0.0.1:"
    ++ U32.show(port) ++ "\r\nConnection: close\r\n\r\n")

def resp_200(r: Result<&1, &1, U32 & String, HTTPX.Response>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      match resp:
        case HTTPX.Response{+status, +headers, +body}:
          b2u(U32.is_eq(status, 200))

def eof_part(r: Result<&1, &1, U32 & String, List<&2, U32>>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+part}:
      match part:
        case Nil{}:
          1
        case h <> t:
          0

def close_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>) ->
  IO(Socket & Result<&1, &1, U32 & String, HTTPX.Response>):
  (s, r) = sent
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, HTTPX.Response>,
        (s, Fail{e}))
    case Done{u}:
      HTTPX.x_h1.cli.head(0, (s, Done{Nil{}}), Nil{}, 64n, "GET", False{})

def close_again(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +ans: U32) ->
  IO(U32):
  (s2, r2) = got
  +eof : U32 = eof_part(r2)
  do IO<U32>:
    x : Unit <- TLS.tls_close(s2)
    IO.pure(U32, U32.and(ans, eof))

def close_eof(out: Socket & Result<&1, &1, U32 & String, HTTPX.Response>, +ans: U32) ->
  IO(U32):
  (s, r) = out
  +ok : U32 = U32.and(ans, resp_200(r))
  do IO<U32>:
    again : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <-
      TLS.tls_recv_bytes(s, 16384)
    close_again(again, ok)

def close_dial(conn: Result<&1, &1, U32 & String, Socket>, +port: U32) ->
  IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <-
          TLS.tls_send_bytes(sock, close_raw(port))
        out : Socket & Result<&1, &1, U32 & String, HTTPX.Response> <-
          close_sent(sent)
        close_eof(out, 1)

def run_close(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, batch_side(l))
    conn : Result<&1, &1, U32 & String, Socket> <-
      TLS.tls_connect_noalpn_insecure("127.0.0.1", port)
    close_dial(conn, port)

# Scenario D: the plaintext mirror. The same three-requests-one-connection
# shape over Base's TCP through x_h1p.exch.send. x_h1p.srv is a copy of
# the TLS machine, not a shared template, so its keep-alive needs its own
# proof — a divergence would leave this at 1 instead of 3.
def plain_end(got: Socket & Result<&1, &1, U32 & String, HTTPX.Response>, +want: String, +sum: U32) ->
  IO(U32):
  (sock, r) = got
  +acc : U32 = (sum + score_echo(want, r) : U32)
  do IO<U32>:
    x : Unit <- Socket.close(sock)
    IO.pure(U32, acc)

@unsafe
def plain_next(got: Socket & Result<&1, &1, U32 & String, HTTPX.Response>, +port: U32, +want: String, +next: String, +more: List<String>, +sum: U32) ->
  IO(U32):
  (sock, r) = got
  +acc : U32 = (sum + score_echo(want, r) : U32)
  do IO<U32>:
    out : Socket & Result<&1, &1, U32 & String, HTTPX.Response> <-
      HTTPX.x_h1p.exch.send(sock, req_bytes(port, next), "POST")
    plain_step(out, port, next, more, acc)

@unsafe
def plain_step(got: Socket & Result<&1, &1, U32 & String, HTTPX.Response>, +port: U32, +want: String, rest: List<String>, +sum: U32) ->
  IO(U32):
  match rest:
    case Nil{}:
      plain_end(got, want, sum)
    case next <> more:
      plain_next(got, port, want, next, more, sum)

def plain_run(conn: Result<&1, &1, U32 & String, Socket>, +port: U32) ->
  IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        out : Socket & Result<&1, &1, U32 & String, HTTPX.Response> <-
          HTTPX.x_h1p.exch.send(sock, req_bytes(port, "hello-0"), "POST")
        plain_step(out, port, "hello-0", ["hello-1", "hello-2"], 0)

def plain_side(l: Listener) -> IO(U32):
  do IO<U32>:
    x : Unit <- HTTPX.server.on_h1_plain(~echo, l)
    IO.pure(U32, 0)

def run_plain(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, plain_side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", port)
    plain_run(conn, port)

# Scenario E: the same batch through the unified client API. client.on
# dials once (ALPN http/1.1 against the server's offer=3) and
# client.on.batch_st sends is_h2=False down the H1 sequential lane — the
# branch that used to close the socket with Fail 615. The server is
# once_h1 (ONE accept), so 3 responses can only come out if all three
# requests rode that one connection.
def resp_body_is(+want: String, resp: HTTPX.Response) -> U32:
  match resp:
    case HTTPX.Response{+status, +headers, +body}:
      b2u(Bool.and(U32.is_eq(status, 200),
        U32.is_eq(HTTPX.x_eq(body, HTTPX.x_str_bytes(want)), 1)))

def batch_score_go(wants: List<String>, rs: List<&2, HTTPX.Response>, +sum: U32) ->
  U32:
  match wants:
    case Nil{}:
      match rs:
        case Nil{}:
          sum
        case h <> t:
          0
    case +w <> ws:
      match rs:
        case Nil{}:
          0
        case +r <> rt:
          batch_score_go(ws, rt, (sum + resp_body_is(w, r) : U32))

def batch_score(wants: List<String>, r: Result<&1, &1, U32 & String, List<&2, HTTPX.Response>>) ->
  U32:
  match r:
    case Fail{e}:
      0
    case Done{+rs}:
      batch_score_go(wants, rs, 0)

def batch_reqs() -> List<&2, HTTPX.Request>:
  [HTTPX.Request{"POST", "/echo", Nil{}, HTTPX.x_str_bytes("hello-0")},
   HTTPX.Request{"POST", "/echo", Nil{}, HTTPX.x_str_bytes("hello-1")},
   HTTPX.Request{"POST", "/echo", Nil{}, HTTPX.x_str_bytes("hello-2")}]

def api_batch(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, List<&2, HTTPX.Response>> <-
      HTTPX.client.on_insecure("127.0.0.1", port, batch_reqs())
    IO.pure(U32, batch_score(["hello-0", "hello-1", "hello-2"], r))

def run_api(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, batch_side(l))
    api_batch(port)

# Scenario F: the keep-alive single-request entry (client.request) on an
# H1 connection. client.connect_insecure hands back the CliSt; two calls
# on that same socket must answer in request order and thread the state.
# The server is once_h1 (ONE accept), so a second dial would hang. Before
# Phase 3 this path wrote H2 frames onto the HTTP/1.1 socket.
def keep_end(got: Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt, +sum: U32) ->
  IO(U32):
  (s2, r2, st2) = got
  +acc : U32 = (sum + score_echo("hello-1", r2) : U32)
  do IO<U32>:
    x : Unit <- TLS.tls_close(s2)
    IO.pure(U32, acc)

def keep_step(got: Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt, +port: U32) ->
  IO(U32):
  (s1, r1, st1) = got
  +a : U32 = score_echo("hello-0", r1)
  do IO<U32>:
    got2 : Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt <-
      HTTPX.client.request(s1, st1, "127.0.0.1", port, "POST", "/echo", Nil{},
        HTTPX.x_str_bytes("hello-1"))
    keep_end(got2, a)

def keep_run(conn: Result<&1, &1, U32 & String, Socket & HTTPX.CliSt>, +port: U32) ->
  IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, st) = value
      do IO<U32>:
        got1 : Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt <-
          HTTPX.client.request(sock, st, "127.0.0.1", port, "POST", "/echo",
            Nil{}, HTTPX.x_str_bytes("hello-0"))
        keep_step(got1, port)

def run_keep(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, batch_side(l))
    conn : Result<&1, &1, U32 & String, Socket & HTTPX.CliSt> <-
      HTTPX.client.connect_insecure("127.0.0.1", port)
    keep_run(conn, port)

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
    +pure : U32 = vectors()
    b1 : Listener & U32 <- listen_any(32n, 18512)
    +batch : U32 <- run_batch(b1)
    b2 : Listener & U32 <- listen_any(32n, 18513)
    +once : U32 <- run_once(b2)
    b3 : Listener & U32 <- listen_any(32n, 18514)
    +close : U32 <- run_close(b3)
    b4 : Listener & U32 <- listen_any(32n, 18515)
    +plain : U32 <- run_plain(b4)
    b5 : Listener & U32 <- listen_any(32n, 18516)
    +api : U32 <- run_api(b5)
    b6 : Listener & U32 <- listen_any(32n, 18517)
    +keep : U32 <- run_keep(b6)
    +total : U32 = (pure + batch + once + close + plain + api + keep : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|14
