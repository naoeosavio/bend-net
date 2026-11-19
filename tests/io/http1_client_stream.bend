# io (http1_client_stream): the TASK-081 Phase 3 client loop of
# lib/http1.bend, driven directly (no facade in the path). Ten cases,
# one connection each, all over plaintext TCP templates:
#   1. once_echo ......... client.once against the module's buffered
#                         fold server: the whole answer in one Response.
#   2. on_fold ............ client.on, two POSTs on the one connection
#                         the single-accept server owns: both answers,
#                         in request order.
#   3. stream_counts ...... client.stream.once, counts only: 5 bytes,
#                         1 chunk.
#   4. stream_chunked ..... client.stream.once against a canned chunked
#                         answer of two chunks: 9 bytes, 2 chunks (the
#                         last chunk carries the fin flag, so the count
#                         stops at the data events).
#   5. stream_on .......... client.stream.on, two requests on the one
#                         connection: the counts add up.
#   6. stream_cancel ...... the handler cancels at the head event: the
#                         entry closes and answers Fail 8.
#   7. fold_eof ........... the peer closes mid-body: Fail 400.
#   8. fold_bad .......... a malformed chunked answer: Fail 400.
#   9. on_seed ........... the canned peer pipelines both answers in
#                         one send: the second rides the leftover of
#                         the first, so the on lane proves it keeps and
#                         re-seeds those bytes.
#  10. info_bad .......... an interim 1xx head with a malformed header
#                         block: the fold parses the whole head before
#                         it drops an interim one, so the answer is the
#                         parse error (400, "bad header"). The read
#                         chain the fold replaces waited for a next
#                         head that never comes.
# Golden 10.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/http1.bend as HTTP1
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# The buffered fold server: echoes the folded request body, keep-alive.
def echo(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, body})

# The stream handler that never stops the read.
def h_all(ev: HTTP.StreamEv) -> HTTP.StreamOut:
  match ev:
    case HTTP.StreamHead{head}:
      HTTP.StreamContinue{}
    case HTTP.StreamData{chunk, fin}:
      HTTP.StreamContinue{}

# The stream handler that cancels at the head event.
def h_cancel(ev: HTTP.StreamEv) -> HTTP.StreamOut:
  match ev:
    case HTTP.StreamHead{head}:
      HTTP.StreamCancel{}
    case HTTP.StreamData{chunk, fin}:
      HTTP.StreamCancel{}

# Request builders.
def req(+body: String) -> HTTP.Request:
  HTTP.Request{"POST", "/echo", Nil{}, HTTP.x_str_bytes(body)}

def reqs2(+a: String, +b: String) -> List<&2, HTTP.Request>:
  [req(a), req(b)]

# Canned answers.
def resp_chunked() -> String:
  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"

# 'z' is not a hex size: the decoder answers Bad at once.
def resp_bad() -> String:
  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nAB"

# The head claims 5 bytes and the side closes after 2: eof mid-body.
def resp_eof() -> String:
  "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi"

# Both answers in one send: the second is the leftover of the first.
def resp_pipe() -> String:
  "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nhi-0"
    ++ "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nhi-1"

# An interim 1xx head whose header block is malformed.
def resp_info_bad() -> String:
  "HTTP/1.1 100 Continue\r\nX-Interim\r\n\r\n"

# Scoring helpers: each matches its own parameter, one marker set each.
def score_fold(r: Result<&1, &1, U32 & String, HTTP.Response>, +want: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      match resp:
        case HTTP.Response{+status, +headers, +body}:
          b2u(Bool.and(U32.is_eq(status, 200),
            U32.is_eq(HTTP.x_eq(body, HTTP.x_str_bytes(want)), 1)))

def score_counts(r: Result<&1, &1, U32 & String, U32 & U32>, +want_t: U32, +want_c: U32) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{counts}:
      match counts:
        case (t, c):
          b2u(Bool.and(U32.is_eq(t, want_t), U32.is_eq(c, want_c)))

def score_cancel(r: Result<&1, &1, U32 & String, U32 & U32>) -> U32:
  match r:
    case Fail{e}:
      (code, msg) = e
      b2u(U32.is_eq(code, 8))
    case Done{counts}:
      0

def score_err_resp(r: Result<&1, &1, U32 & String, HTTP.Response>, +want: U32) -> U32:
  match r:
    case Fail{e}:
      (code, msg) = e
      b2u(U32.is_eq(code, want))
    case Done{+resp}:
      0

def score_err_msg(r: Result<&1, &1, U32 & String, HTTP.Response>, +want: U32, +msg: String) -> U32:
  match r:
    case Fail{e}:
      (code, m) = e
      b2u(Bool.and(U32.is_eq(code, want), String.eq(m, msg)))
    case Done{+resp}:
      0

def score_on2(r: Result<&1, &1, U32 & String, List<&2, HTTP.Response>>, +w1: String, +w2: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+rs}:
      match rs:
        case HTTP.Response{+s1, +h1, +b1} <> HTTP.Response{+s2, +h2, +b2} <> Nil{}:
          b2u(Bool.and(U32.is_eq(s1, 200),
            Bool.and(U32.is_eq(HTTP.x_eq(b1, HTTP.x_str_bytes(w1)), 1),
              Bool.and(U32.is_eq(s2, 200),
                U32.is_eq(HTTP.x_eq(b2, HTTP.x_str_bytes(w2)), 1)))))
        case _:
          0

# The canned peer: accept, send the bytes, then hold the socket open
# until the client closes (the drain), so no send of the client meets a
# closed socket.
@unsafe
def drain_go(got: Socket & Result<&1, &1, U32 & String, String>, fuel: Nat) -> IO(Unit):
  (s2, part) = got
  match part:
    case Fail{e}:
      Socket.close(s2)
    case Done{+txt}:
      match txt:
        case SNil{}:
          Socket.close(s2)
        case SCon{h, t}:
          match fuel:
            case 0n:
              Socket.close(s2)
            case 1n+f:
              do IO<Unit>:
                got2 : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s2, 16384)
                drain_go(got2, f)

def drain_start(s: Socket, fuel: Nat) -> IO(Unit):
  do IO<Unit>:
    got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 16384)
    drain_go(got, fuel)

def after_drain(s: Socket) -> IO(Unit):
  drain_start(s, 64n)

# The eof side closes AFTER it drains the request: a close with unread
# bytes answers RST, and the RST can eat the queued answer bytes.
def after_eof.drain(got: Socket & Result<&1, &1, U32 & String, String>) -> IO(Unit):
  (s2, _r) = got
  Socket.close(s2)

def after_eof(s: Socket) -> IO(Unit):
  do IO<Unit>:
    got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 16384)
    after_eof.drain(got)

def raw_side.sent(~after: Socket -> IO(Unit), sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, _r) = sent
  after(s)

def raw_side.m(~after: Socket -> IO(Unit), m: Listener & Result<&1, &1, U32 & String, Socket>, +bytes: String) -> IO(Unit):
  (l2, r) = m
  match r:
    case Fail{e}:
      IO.pure(Unit, Unit{})
    case Done{sock}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, bytes)
        raw_side.sent(~after, sent)

def raw_side(~after: Socket -> IO(Unit), l: Listener, +bytes: String) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    raw_side.m(~after, m, bytes)

# Server sides.
def side_fold(l: Listener) -> IO(Unit):
  HTTP1.server.once(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, ~TCP.accept, ~echo, l)

def side_chunked(l: Listener) -> IO(Unit):
  raw_side(~after_drain, l, resp_chunked())

def side_bad(l: Listener) -> IO(Unit):
  raw_side(~after_drain, l, resp_bad())

def side_eof(l: Listener) -> IO(Unit):
  raw_side(~after_eof, l, resp_eof())

def side_pipe(l: Listener) -> IO(Unit):
  raw_side(~after_drain, l, resp_pipe())

def side_info(l: Listener) -> IO(Unit):
  raw_side(~after_drain, l, resp_info_bad())

# The one client exchange each case drives. The port and the socket are
# plain parameters, so every def here fits the runner's template.
def cli_once_echo(port: U32, sock: Socket) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTP1.client.once(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, sock, "127.0.0.1", port, "POST", "/echo", Nil{}, HTTP.x_str_bytes("hello"))
    IO.pure(U32, score_fold(r, "hello"))

def cli_on_fold(port: U32, sock: Socket) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, List<&2, HTTP.Response>> <- HTTP1.client.on(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, sock, "127.0.0.1", port, reqs2("hi-0", "hi-1"))
    IO.pure(U32, score_on2(r, "hi-0", "hi-1"))

def cli_stream_counts(port: U32, sock: Socket) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <- HTTP1.client.stream.once(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, ~h_all, sock, "127.0.0.1", port, "POST", "/echo", Nil{}, HTTP.x_str_bytes("hello"))
    IO.pure(U32, score_counts(r, 5, 1))

def cli_stream_chunked(port: U32, sock: Socket) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <- HTTP1.client.stream.once(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, ~h_all, sock, "127.0.0.1", port, "POST", "/echo", Nil{}, Nil{})
    IO.pure(U32, score_counts(r, 9, 2))

def cli_stream_on(port: U32, sock: Socket) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <- HTTP1.client.stream.on(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, ~h_all, sock, "127.0.0.1", port, reqs2("a", "b"))
    IO.pure(U32, score_counts(r, 2, 2))

def cli_stream_cancel(port: U32, sock: Socket) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <- HTTP1.client.stream.once(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, ~h_cancel, sock, "127.0.0.1", port, "POST", "/echo", Nil{}, HTTP.x_str_bytes("hello"))
    IO.pure(U32, score_cancel(r))

def cli_fold_eof(port: U32, sock: Socket) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTP1.client.once(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, sock, "127.0.0.1", port, "POST", "/echo", Nil{}, HTTP.x_str_bytes("hello"))
    IO.pure(U32, score_err_resp(r, 400))

def cli_fold_bad(port: U32, sock: Socket) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTP1.client.once(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, sock, "127.0.0.1", port, "POST", "/echo", Nil{}, HTTP.x_str_bytes("hello"))
    IO.pure(U32, score_err_resp(r, 400))

def cli_on_seed(port: U32, sock: Socket) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, List<&2, HTTP.Response>> <- HTTP1.client.on(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, sock, "127.0.0.1", port, reqs2("hi-0", "hi-1"))
    IO.pure(U32, score_on2(r, "hi-0", "hi-1"))

def cli_info_bad(port: U32, sock: Socket) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTP1.client.once(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, sock, "127.0.0.1", port, "POST", "/echo", Nil{}, HTTP.x_str_bytes("hello"))
    IO.pure(U32, score_err_msg(r, 400, "bad header"))

# The harness: fork the side, dial, drive the client def.
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

def run_client.go(~cli: U32 -> Socket -> IO(U32), port: U32, conn: Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      cli(port, sock)

def run_client(~side: Listener -> IO(Unit), ~cli: U32 -> Socket -> IO(U32), b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", port)
    run_client.go(~cli, port, conn)

def case_client(~side: Listener -> IO(Unit), ~cli: U32 -> Socket -> IO(U32), +port: U32) -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(8n, port)
    run_client(~side, ~cli, b)

def main() -> IO(U32):
  do IO<U32>:
    a : U32 <- case_client(~side_fold, ~cli_once_echo, 20640)
    b : U32 <- case_client(~side_fold, ~cli_on_fold, 20641)
    c : U32 <- case_client(~side_fold, ~cli_stream_counts, 20642)
    d : U32 <- case_client(~side_chunked, ~cli_stream_chunked, 20643)
    e : U32 <- case_client(~side_fold, ~cli_stream_on, 20644)
    f : U32 <- case_client(~side_fold, ~cli_stream_cancel, 20645)
    g : U32 <- case_client(~side_eof, ~cli_fold_eof, 20646)
    h : U32 <- case_client(~side_bad, ~cli_fold_bad, 20647)
    i : U32 <- case_client(~side_pipe, ~cli_on_seed, 20648)
    j : U32 <- case_client(~side_info, ~cli_info_bad, 20649)
    +total : U32 = (a + b + c + d + e + f + g + h + i + j : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|10
