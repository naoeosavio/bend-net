# io (http1_client_stream): the TASK-081 Phase 3 client lanes of
# lib/http1.bend, driven directly (no facade in the path). Twelve
# cases, one connection each. The client entries dial themselves, so
# every case forks a side and hands the entry the port:
#   1. once_echo ......... client.once (TCP): the whole answer in one
#                         Response against the module's buffered fold
#                         server.
#   2. on_fold ............ client.on (TCP), two POSTs on the one
#                         connection the single-accept server owns:
#                         both answers, in request order.
#   3. stream_counts ...... client.stream.once (TCP), counts only:
#                         5 bytes, 1 chunk.
#   4. stream_chunked ..... client.stream.once against a canned chunked
#                         answer of two chunks: 9 bytes, 2 chunks (the
#                         last chunk carries the fin flag, so the count
#                         stops at the data events).
#   5. stream_on .......... client.stream.on (TCP), two requests on
#                         the one connection: the counts add up.
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
#  11. secure_refuse ..... client.once_secure against a self-signed
#                         cert: the verified dial refuses it, Fail 614
#                         ("verify failed"), before any byte leaves.
#  12. tls_insecure ....... client.once_insecure over the no-verify
#                         dial: the same loop through the TLS triple,
#                         the echo scored. The insecure mode is the one
#                         every loopback test needs, so it owns a named
#                         entry, the H2 twin's name.
#  13. fold_cap .......... a canned answer head of more than 70 KB with
#                         no blank line anywhere: past the 64 KiB
#                         client budget the fold's head read answers
#                         Fail 413, the code of its fuel floor, and
#                         the process stays alive.
#  14. fold_reopen ....... a valid 200 answer head of ~24 KiB, past
#                         the old 16 KiB budget: the fold parses it
#                         (TASK-081 Phase 4.5 reopened the window).
#  15. fold_many ......... a valid answer head of 8000 short lines
#                         (~56 KiB): the tail parse fold answers
#                         without a fault.
#  16. fold_line ......... one answer line of 20 KB: the per-line gate
#                         answers Fail 400 "line too long".
#  17. big_resp .......... the handler answers 3000 headers (~39 KB):
#                         the render must survive its own answer (the
#                         old render's List.append was quadratic and
#                         faulted near 32k cells).
#  18. req_big ........... the request itself carries 3000 headers: the
#                         client renders it without a fault; the module
#                         server would refuse the head, so the side is
#                         a lenient canned peer.
#  19. fold_big_chunk .... one single chunk of 64 KB through the fold:
#                         the machine consumes every turn and the
#                         fragment assembly rides chunk_close with the
#                         fragment (<=16k) on the first side, so the
#                         answer is the whole body (the "buffer wall"
#                         the log once registered was a misread,
#                         measured dead).
#  20. fold_500 .......... a canned 500 answer with Content-Length: 0:
#                         the fold answers the empty body, it never
#                         asks for more on a satisfied need (the
#                         TASK-082 fix of the cl cut; the old NeedMore
#                         starved a keep-alive recv forever).
# Golden 20.
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

# 3000 headers of "x-pad: aaaa": a ~39 KB block, past the old render
# wall (Base's List.append faults near 32k cells on its first side).
def pad_hdrs(n: Nat, acc: List<&2, HTTP.Hdr>) -> List<&2, HTTP.Hdr>:
  match n:
    case 0n:
      acc
    case 1n+p:
      pad_hdrs(p, HTTP.Hdr{"x-pad", "aaaa"} <> acc)

def big_hs() -> List<&2, HTTP.Hdr>:
  pad_hdrs(3000n, Nil{})

# The big-header answer handler.
def big_h(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{200, big_hs(), body})

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

# The over-long answer head: more than 60 KB, no blank line anywhere.
# Tail builder, because List.replicate is not tail-recursive (the
# measured lesson of the bench file).
def pad(n: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      pad(p, 65 <> acc)

def resp_cap() -> List<&2, U32>:
  List.append(&2, U32, HTTP.x_str_bytes("HTTP/1.1 200 OK\r\nX-Pad: "), pad(70000n, Nil{}))

# The line builder of the valid big heads: n copies of one short
# line, pushed in final order (x_cat un-reverses the whole at the
# end).
def pad_lines(n: Nat, +line: String, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      pad_lines(p, line, HTTP.x_rev_push(HTTP.x_str_bytes(line), acc))

# The reopened window on the fold: a valid 204 answer head of ~24 KiB,
# every line short. A 204 owns no body, so the fold answers at once.
def resp_reopen() -> String:
  HTTP.x_bytes_str(HTTP.x_cat(HTTP.x_rev_push(HTTP.x_str_bytes("\r\n"), pad_lines(2000n, "x-pad: aaaa\r\n", HTTP.x_rev_push(HTTP.x_str_bytes("HTTP/1.1 204 No Content\r\n"), Nil{})))))

# The many-lines head: 8000 short lines, ~56 KiB, valid, under the
# budget. The parse-depth pin on the fold.
def resp_many() -> String:
  HTTP.x_bytes_str(HTTP.x_cat(HTTP.x_rev_push(HTTP.x_str_bytes("\r\n"), pad_lines(8000n, "a: bb\r\n", HTTP.x_rev_push(HTTP.x_str_bytes("HTTP/1.1 204 No Content\r\n"), Nil{})))))

# One line of 20 KB: the per-line gate answers 400 before any Base
# walk on the line.
def resp_line() -> String:
  HTTP.x_bytes_str(HTTP.x_cat(HTTP.x_rev_push(HTTP.x_str_bytes("\r\n\r\n"), pad(20000n, HTTP.x_rev_push(HTTP.x_str_bytes("x-long: "), HTTP.x_rev_push(HTTP.x_str_bytes("HTTP/1.1 200 OK\r\n"), Nil{}))))))

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

# Case 20: a 500 whose body is empty folds to the answer.
def score_500(r: Result<&1, &1, U32 & String, HTTP.Response>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      match resp:
        case HTTP.Response{+status, +headers, +body}:
          b2u(Bool.and(U32.is_eq(status, 500),
            List.is_empty(&2, U32, body)))

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

# Server sides. The plain one rides the TCP accept; the TLS one rides
# the module's own _secure entry over the test cert.
def side_fold(l: Listener) -> IO(Unit):
  HTTP1.server.once(~echo, l)

def side_big_resp(l: Listener) -> IO(Unit):
  HTTP1.server.once(~big_h, l)

def resp_ok5() -> String:
  "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"

def side_lenient(l: Listener) -> IO(Unit):
  raw_side(~after_drain, l, resp_ok5())

# The 64 KB single chunk (TASK-081 Phase 4.7): the pad nests INSIDE
# the third push -- the pushes evaluate innermost first and ride the
# final order, so the A's must sit between the size line and its
# closing CRLF.
def resp_big_chunk() -> String:
  HTTP.x_bytes_str(HTTP.x_cat(HTTP.x_rev_push(HTTP.x_str_bytes("0\r\n\r\n"), HTTP.x_rev_push(HTTP.x_str_bytes("\r\n"), pad(65536n, HTTP.x_rev_push(HTTP.x_str_bytes("10000\r\n"), HTTP.x_rev_push(HTTP.x_str_bytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"), Nil{})))))))

def side_big_chunk(l: Listener) -> IO(Unit):
  raw_side(~after_drain, l, resp_big_chunk())

# Case 20: the fixed 500 with an empty body, the answer shape the cl
# cut once starved.
def resp_500_cl0() -> String:
  "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"

def side_500(l: Listener) -> IO(Unit):
  raw_side(~after_drain, l, resp_500_cl0())

def side_fold_tls(l: Listener) -> IO(Unit):
  HTTP1.server.once_secure(~echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")

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

# The bytes twin of raw_side: the over-long head is a byte list, not a
# string literal, so the send rides TCP.send_bytes.
def raw_side_b.m(~after: Socket -> IO(Unit), m: Listener & Result<&1, &1, U32 & String, Socket>, +bytes: List<&2, U32>) -> IO(Unit):
  (l2, r) = m
  match r:
    case Fail{e}:
      IO.pure(Unit, Unit{})
    case Done{sock}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send_bytes(sock, bytes)
        raw_side.sent(~after, sent)

def raw_side_b(~after: Socket -> IO(Unit), l: Listener, +bytes: List<&2, U32>) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    raw_side_b.m(~after, m, bytes)

def side_cap(l: Listener) -> IO(Unit):
  raw_side_b(~after_drain, l, resp_cap())

def side_reopen(l: Listener) -> IO(Unit):
  raw_side(~after_drain, l, resp_reopen())

def side_many(l: Listener) -> IO(Unit):
  raw_side(~after_drain, l, resp_many())

def side_line(l: Listener) -> IO(Unit):
  raw_side(~after_drain, l, resp_line())

# One client exchange each case drives. The entry dials, so the port
# is the only argument.
def cli_once_echo(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTP1.client.once("127.0.0.1", port, req("hello"))
    IO.pure(U32, score_fold(r, "hello"))

def cli_on_fold(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, List<&2, HTTP.Response>> <- HTTP1.client.on("127.0.0.1", port, reqs2("hi-0", "hi-1"))
    IO.pure(U32, score_on2(r, "hi-0", "hi-1"))

def cli_stream_counts(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <- HTTP1.client.stream.once(~h_all, "127.0.0.1", port, "POST", "/echo", Nil{}, HTTP.x_str_bytes("hello"))
    IO.pure(U32, score_counts(r, 5, 1))

def cli_stream_chunked(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <- HTTP1.client.stream.once(~h_all, "127.0.0.1", port, "POST", "/echo", Nil{}, Nil{})
    IO.pure(U32, score_counts(r, 9, 2))

def cli_stream_on(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <- HTTP1.client.stream.on(~h_all, "127.0.0.1", port, reqs2("a", "b"))
    IO.pure(U32, score_counts(r, 2, 2))

def cli_stream_cancel(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <- HTTP1.client.stream.once(~h_cancel, "127.0.0.1", port, "POST", "/echo", Nil{}, HTTP.x_str_bytes("hello"))
    IO.pure(U32, score_cancel(r))

def cli_fold_eof(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTP1.client.once("127.0.0.1", port, req("hello"))
    IO.pure(U32, score_err_resp(r, 400))

def cli_fold_bad(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTP1.client.once("127.0.0.1", port, req("hello"))
    IO.pure(U32, score_err_resp(r, 400))

def cli_on_seed(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, List<&2, HTTP.Response>> <- HTTP1.client.on("127.0.0.1", port, reqs2("hi-0", "hi-1"))
    IO.pure(U32, score_on2(r, "hi-0", "hi-1"))

def cli_info_bad(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTP1.client.once("127.0.0.1", port, req("hello"))
    IO.pure(U32, score_err_msg(r, 400, "bad header"))

# The verified dial refuses the self-signed test cert.
def cli_secure_refuse(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTP1.client.once_secure("127.0.0.1", port, req("hello"))
    IO.pure(U32, score_err_resp(r, 614))

# The no-verify TLS entry: one call, the loopback lane.
def cli_once_insecure(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTP1.client.once_insecure("127.0.0.1", port, req("hello"))
    IO.pure(U32, score_fold(r, "hello"))

# The over-long head answers the 413 of the fold's fuel floor, not the
# memory fault of the deep append (TASK-081 Phase 4).
def cli_fold_cap(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTP1.client.once("127.0.0.1", port, req("hello"))
    IO.pure(U32, score_err_resp(r, 413))

# One mark when the answer is the bodiless 204.
def score_204(r: Result<&1, &1, U32 & String, HTTP.Response>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      match resp:
        case HTTP.Response{+status, +headers, +body}:
          b2u(U32.is_eq(status, 204))

# The reopened window on the fold (TASK-081 Phase 4.5): a valid ~24 KiB
# answer head parses; a 204 owns no body, so the fold answers at once.
def cli_fold_reopen(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTP1.client.once("127.0.0.1", port, req("hello"))
    IO.pure(U32, score_204(r))

# The many-lines head: the tail parse fold answers 8000 lines.
def cli_fold_many(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTP1.client.once("127.0.0.1", port, req("hello"))
    IO.pure(U32, score_204(r))

# The per-line gate: one 20 KB line fails closed.
def cli_fold_line(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTP1.client.once("127.0.0.1", port, req("hello"))
    IO.pure(U32, score_err_msg(r, 400, "line too long"))

# The big-header answer (TASK-081 Phase 4.6): the render must survive
# the ~39 KB head the handler answers.
def cli_once_big_resp(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTP1.client.once("127.0.0.1", port, req("hello"))
    IO.pure(U32, score_fold(r, "hello"))

# The big-header request: the client's own render must survive the
# ~39 KB head it sends.
def req_big() -> HTTP.Request:
  HTTP.Request{"POST", "/echo", big_hs(), HTTP.x_str_bytes("hello")}

def cli_req_big(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTP1.client.once("127.0.0.1", port, req_big())
    IO.pure(U32, score_fold(r, "hello"))

# One mark when the answer is 200 with the exact body length.
def score_200_len(r: Result<&1, &1, U32 & String, HTTP.Response>, +want: U32) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      match resp:
        case HTTP.Response{+status, +headers, +body}:
          b2u(Bool.and(U32.is_eq(status, 200), U32.is_eq(HTTP.x_len32(body), want)))

# The 64 KB single chunk through the fold.
def cli_fold_big_chunk(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTP1.client.once("127.0.0.1", port, req("hello"))
    IO.pure(U32, score_200_len(r, 65536))

# Case 20: the 500 with the empty body must fold, not starve.
def cli_fold_500(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, HTTP.Response> <- HTTP1.client.once("127.0.0.1", port, req("hello"))
    IO.pure(U32, score_500(r))

# The harness: fork the side, hand the client def the port.
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

def run_client(~side: Listener -> IO(Unit), ~cli: U32 -> IO(U32), b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, side(l))
    cli(port)

def case_client(~side: Listener -> IO(Unit), ~cli: U32 -> IO(U32), +port: U32) -> IO(U32):
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
    k : U32 <- case_client(~side_fold_tls, ~cli_secure_refuse, 20650)
    l : U32 <- case_client(~side_fold_tls, ~cli_once_insecure, 20651)
    m : U32 <- case_client(~side_cap, ~cli_fold_cap, 20652)
    n : U32 <- case_client(~side_reopen, ~cli_fold_reopen, 20653)
    o : U32 <- case_client(~side_many, ~cli_fold_many, 20654)
    p : U32 <- case_client(~side_line, ~cli_fold_line, 20655)
    q : U32 <- case_client(~side_big_resp, ~cli_once_big_resp, 20656)
    r : U32 <- case_client(~side_lenient, ~cli_req_big, 20657)
    s : U32 <- case_client(~side_big_chunk, ~cli_fold_big_chunk, 20658)
    t : U32 <- case_client(~side_500, ~cli_fold_500, 20659)
    +total : U32 = (a + b + c + d + e + f + g + h + i + j + k + l + m + n + o + p + q + r + s + t : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|20
