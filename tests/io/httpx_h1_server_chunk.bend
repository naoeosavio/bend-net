# httpx (lib_httpx_h1_server_chunk): the H1 server lane against a chunked
# request. Before TASK-033 a request with Transfer-Encoding: chunked was
# answered 502 before the handler ever saw it, on both the keep-alive lane
# (x_h1.srv.go) and the upgrade lane (x_h1.srv.go_open).
#
# One plaintext server (server.on_h1_plain) whose handler echoes the body
# back as "OK:" ++ body, and one raw TCP client per case:
# 1. a two-chunk POST with an extension -> the handler sees "Wikipedia";
# 2. the same request written in two sends -> same body (the reader has to
#    resume from its own state across reads);
# 3. a size line that is not hex -> a 400 answer on the wire, not a hang
#    and not a silent drop;
# 4. a body over the 16384 cap -> 413, the same cap and code the
#    Content-Length path uses. The vector carries the terminator because a
#    chunk is only reported once it is whole AND the lookahead has seen the
#    next byte (that is what tells the machine which chunk is the last), and
#    the cap is checked before anything else on the iteration that follows a
#    reported chunk -- that ordering is what makes an over-cap body answer
#    413 instead of reaching the handler. A peer that declares an over-cap
#    chunk and then stalls is a different case, and the same one the
#    Content-Length lane has: the reader blocks on recv until the peer sends
#    or closes, with memory bounded by the fuel floor (64 recvs);
# 5. two chunked requests on ONE connection -> both answered, which is the
#    proof that the leftover bytes after the terminator ride back into the
#    keep-alive machine as the next request's seed;
# 6. the same chunked POST against server.on_h1_open_plain, whose handler
#    does NOT upgrade, so the request has to travel go_open -> chunk_open
#    -> answer_open -> rejoin.
# Golden 6.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# The handler: 200 with the request body echoed as text, so the raw client
# can read the decoded body straight out of the response.
def echo_body(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, HTTP.x_str_bytes("OK:" ++ HTTP.x_bytes_str(body))})

# The ~K of the upgrade lane: only a 101 would call it, and this handler
# never answers 101, so it just closes (kept a plain def, not IO.die, so a
# surprise upgrade would end the case instead of the process).
def k_close(sock: Socket, rest: List<&2, U32>) -> IO(Unit):
  Socket.close(sock)

def has(r: Result<&1, &1, U32 & String, String>, +want: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+raw}:
      b2u(String.contains(raw, want))

def close_score(got: Socket & Result<&1, &1, U32 & String, String>, +want: String) -> IO(U32):
  (s, r) = got
  do IO<U32>:
    +score : U32 = has(r, want)
    x : Unit <- Socket.close(s)
    IO.pure(U32, score)

def send_wait(sent: Socket & Result<&1, &1, U32 & String, Unit>, +want: String) -> IO(U32):
  (s, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 16384)
        close_score(got, want)

# One request, one response.
def raw_case(conn: Result<&1, &1, U32 & String, Socket>, +req: String, +want: String) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req)
        send_wait(sent, want)

# One request in two writes.
def two_sent2(sent1: Socket & Result<&1, &1, U32 & String, Unit>, +part2: String, +want: String) -> IO(U32):
  (s1, r1) = sent1
  match r1:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s1)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        sent2 : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(s1, part2)
        send_wait(sent2, want)

def raw_split(conn: Result<&1, &1, U32 & String, Socket>, +part1: String, +part2: String, +want: String) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        sent1 : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, part1)
        two_sent2(sent1, part2, want)

# Two requests on one connection, in order: response one, then request two,
# then response two.
def keep_read2(sent2: Socket & Result<&1, &1, U32 & String, Unit>, +a: U32, +want2: String) -> IO(U32):
  (s2, r2) = sent2
  match r2:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s2)
        IO.pure(U32, a)
    case Done{u}:
      do IO<U32>:
        got2 : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s2, 16384)
        close_score(got2, want2)

def keep_send2(got1: Socket & Result<&1, &1, U32 & String, String>, +want1: String, +req2: String, +want2: String) -> IO(U32):
  (s1, r1) = got1
  do IO<U32>:
    +a : U32 = has(r1, want1)
    sent2 : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(s1, req2)
    keep_read2(sent2, a, want2)

def keep_sent1(sent1: Socket & Result<&1, &1, U32 & String, Unit>, +want1: String, +req2: String, +want2: String) -> IO(U32):
  (s, r) = sent1
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got1 : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 16384)
        keep_send2(got1, want1, req2, want2)

def raw_keep(conn: Result<&1, &1, U32 & String, Socket>, +req1: String, +want1: String, +req2: String, +want2: String) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        sent1 : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req1)
        keep_sent1(sent1, want1, req2, want2)

# Request texts. A chunked POST whose body is the RFC 9112 shape.
def req_tail(close_it: Bool) -> String:
  match close_it:
    case True{}:
      "Connection: close\r\n\r\n"
    case False{}:
      "\r\n"

def req_chunked(+close_it: Bool) -> String:
  "POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n"
    ++ req_tail(close_it)
    ++ "4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\n\r\n"

def req_bad() -> String:
  "POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nzz\r\nAB"

# A body that decodes to more than the server's 16384 cap: 20000 bytes
# (0x4E20) of 'A' in one chunk.
@unsafe
def filler.go(+n: U32, +acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0:
      acc
    case _:
      filler.go((n - 1 : U32), 65 <> acc)

def filler(n: U32) -> String:
  HTTP.x_bytes_str(filler.go(n, Nil{}))

def req_over() -> String:
  "POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4E20\r\n" ++ filler(20000) ++ "\r\n0\r\n\r\n"


def listen_retry(port: U32, r: Result<&1, &1, U32 & String, Listener>, rest: IO(Listener & U32)) -> IO(Listener & U32):
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
        r : Result<&1, &1, U32 & String, Listener> <- TCP.listen(port)
        listen_retry(port, r, rest)

def plain_side(l: Listener) -> IO(Unit):
  HTTPX.server.on_h1_plain(~echo_body, l)

def open_side(l: Listener) -> IO(Unit):
  HTTPX.server.on_h1_open_plain(~echo_body, ~k_close, l)

def case_two(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, plain_side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", port)
    raw_case(conn, req_chunked(True{}), "OK:Wikipedia")

def case_split(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, plain_side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", port)
    raw_split(conn, "POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nWi", "ki\r\n5;ext=1\r\npedia\r\n0\r\n\r\n", "OK:Wikipedia")

def case_bad(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, plain_side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", port)
    raw_case(conn, req_bad(), "400")

def case_over(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, plain_side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", port)
    raw_case(conn, req_over(), "413")

def case_keep(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, plain_side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", port)
    raw_keep(conn, req_chunked(False{}), "OK:Wikipedia", "POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nWiki\r\n0\r\n\r\n", "OK:Wiki")

def case_open(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, open_side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", port)
    raw_case(conn, req_chunked(True{}), "OK:Wikipedia")

def main() -> IO(Unit):
  do IO<Unit>:
    b1 : Listener & U32 <- listen_any(32n, 49330)
    b2 : Listener & U32 <- listen_any(32n, 49331)
    b3 : Listener & U32 <- listen_any(32n, 49332)
    b4 : Listener & U32 <- listen_any(32n, 49333)
    b5 : Listener & U32 <- listen_any(32n, 49334)
    b6 : Listener & U32 <- listen_any(32n, 49335)
    a : U32 <- case_two(b1)
    c : U32 <- case_split(b2)
    d : U32 <- case_bad(b3)
    e : U32 <- case_over(b4)
    f : U32 <- case_keep(b5)
    g : U32 <- case_open(b6)
    +total : U32 = (a + c + d + e + f + g : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return z

#|6
