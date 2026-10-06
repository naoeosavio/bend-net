# httpx (lib_httpx_h1_fetch_chunk): the H1 client lane against a chunked
# response. Before TASK-033 the lane refused Transfer-Encoding: chunked
# with 502 "chunked refused", and since a large slice of the web answers
# only chunked (examples/httpx_h1_real.bend: example.com and
# httpforever.com), that was the whole client's reach.
#
# Every case is a canned raw server on its own port: accept, read the
# request, write one fixed response, close. Eight cases:
# 1. two chunks plus an extension, read as text -> "Wikipedia";
# 2. the same bytes through fetch_bytes_insecure -> the same bytes;
# 3. three 16 KiB chunks (49 KB of body), which is more than one recv
#    buffer, so the reader has to resume from its own state across reads;
# 4. a chunk truncated by the close -> 400, never 502 and never a short
#    body read as a whole one;
# 5. a size line that is not hex -> 400;
# 6. a trailer section -> 400 (the same answer the reference decoder
#    gives: a trailer is not chunked data);
# 7. HEAD with a chunked body -> the no-body rule still wins, body empty;
# 8. Content-Length AND Transfer-Encoding: chunked -> chunked wins
#    (RFC 9112 section 6.3), so the body is the chunked one, not 5 bytes.
# Golden 8.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# 1 iff the response body is exactly this text.
def text_is(r: Result<&1, &1, U32 & String, String>, +want: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+body}:
      b2u(String.eq(body, want))

# 1 iff the response failed with exactly this code. A Done scores 0, so a
# case that wanted a refusal cannot pass on a body.
def code_is(r: Result<&1, &1, U32 & String, String>, +code: U32) -> U32:
  match r:
    case Fail{e}:
      (c, m) = e
      b2u(U32.is_eq(c, code))
    case Done{body}:
      0

# 1 iff the byte body is exactly this long.
def bytes_len_is(r: Result<&1, &1, U32 & String, List<&2, U32>>, +want: U32) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+bs}:
      b2u(U32.is_eq(HTTPX.x_len32(bs), want))

# The canned server: one accept, one read of the request, one write, close.
def srv_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>, l: Listener) -> IO(U32):
  (s2, r2) = sent
  do IO<U32>:
    x : Unit <- Socket.close(s2)
    y : Unit <- Listener.close(l)
    IO.pure(U32, 0)

def srv_send(got: Socket & Result<&1, &1, U32 & String, String>, l: Listener, +text: String) -> IO(U32):
  (s, r) = got
  do IO<U32>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(s, text)
    srv_sent(sent, l)

def srv_conn(m: Listener & Result<&1, &1, U32 & String, Socket>, +text: String) -> IO(U32):
  (l, r) = m
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Listener.close(l)
        IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(sock, 8192)
        srv_send(got, l, text)

def srv_side(l: Listener, +text: String) -> IO(U32):
  do IO<U32>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    srv_conn(m, text)

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

def url(port: U32) -> String:
  "http://127.0.0.1:" ++ U32.show(port) ++ "/"

# The body of case 3: three 16 KiB chunks, built once as text and sent by
# the canned server in a single write (the client still reads it in
# several recvs, which is the point of the case).
@unsafe
def pay.go(+n: U32, +acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0:
      acc
    case _:
      pay.go((n - 1 : U32), 65 <> acc)

# The filler byte is 'A' (65) and not n & 255 on purpose: the canned
# server's payload is a String and every code point above 127 rides the
# wire as TWO UTF-8 bytes, so a "16384 byte" chunk of arbitrary byte
# values arrives with the wrong length and the framing check refuses it.
# A real byte-lane vector would build the response with TCP.send_bytes.
def pay(n: U32) -> String:
  HTTPX.x_bytes_str(pay.go(n, Nil{}))

def chunk_text() -> String:
  "4000\r\n" ++ pay(16384) ++ "\r\n"

def big_body_text() -> String:
  String.concat([chunk_text(), chunk_text(), chunk_text(), "0\r\n\r\n"])

# Case 1: two chunks, one with an extension, read as text.
def case_two(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(U32) <- IO.fork(U32, srv_side(l, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\n\r\n"))
    r : Result<&1, &1, U32 & String, String> <- HTTPX.fetch_insecure(url(port))
    x : U32 <- IO.join(U32, chan)
    IO.pure(U32, text_is(r, "Wikipedia"))

# Case 2: the same body through the bytes entry point.
def case_two_bytes(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(U32) <- IO.fork(U32, srv_side(l, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\n\r\n"))
    r : Result<&1, &1, U32 & String, List<&2, U32>> <- HTTPX.fetch_bytes_insecure(url(port))
    x : U32 <- IO.join(U32, chan)
    IO.pure(U32, bytes_len_is(r, 9))

# Case 3: 3 x 16 KiB of body, more than one recv buffer.
def case_big(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(U32) <- IO.fork(U32, srv_side(l, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" ++ big_body_text()))
    r : Result<&1, &1, U32 & String, List<&2, U32>> <- HTTPX.fetch_bytes_insecure(url(port))
    x : U32 <- IO.join(U32, chan)
    IO.pure(U32, bytes_len_is(r, 49152))

# Case 4: the peer closes in the middle of a chunk.
def case_truncated(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(U32) <- IO.fork(U32, srv_side(l, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nWi"))
    r : Result<&1, &1, U32 & String, String> <- HTTPX.fetch_insecure(url(port))
    x : U32 <- IO.join(U32, chan)
    IO.pure(U32, code_is(r, 400))

# Case 5: a size line that is not hex.
def case_bad_hex(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(U32) <- IO.fork(U32, srv_side(l, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nzz\r\nAB\r\n0\r\n\r\n"))
    r : Result<&1, &1, U32 & String, String> <- HTTPX.fetch_insecure(url(port))
    x : U32 <- IO.join(U32, chan)
    IO.pure(U32, code_is(r, 400))

# Case 6: a trailer section after the last chunk.
def case_trailer(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(U32) <- IO.fork(U32, srv_side(l, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\nA\r\n0\r\nX: y\r\n\r\n"))
    r : Result<&1, &1, U32 & String, String> <- HTTPX.fetch_insecure(url(port))
    x : U32 <- IO.join(U32, chan)
    IO.pure(U32, code_is(r, 400))

# Case 7: HEAD asks for no body whatever the framing says.
def case_head(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(U32) <- IO.fork(U32, srv_side(l, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n"))
    r : Result<&1, &1, U32 & String, String> <- HTTPX.request_plain("127.0.0.1", port, "/", "HEAD", Nil{}, "")
    x : U32 <- IO.join(U32, chan)
    IO.pure(U32, text_is(r, ""))

# Case 8: both framings on one head. Transfer-Encoding wins (RFC 9112
# section 6.3: a sender must not send both, and a recipient that sees both
# must ignore Content-Length), so the body is the chunked "Wikipedia" and
# not the 5 bytes the Content-Length asks for.
def case_both(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(U32) <- IO.fork(U32, srv_side(l, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\n\r\n"))
    r : Result<&1, &1, U32 & String, String> <- HTTPX.fetch_insecure(url(port))
    x : U32 <- IO.join(U32, chan)
    IO.pure(U32, text_is(r, "Wikipedia"))

def main() -> IO(Unit):
  do IO<Unit>:
    b1 : Listener & U32 <- listen_any(32n, 49310)
    b2 : Listener & U32 <- listen_any(32n, 49311)
    b3 : Listener & U32 <- listen_any(32n, 49312)
    b4 : Listener & U32 <- listen_any(32n, 49313)
    b5 : Listener & U32 <- listen_any(32n, 49314)
    b6 : Listener & U32 <- listen_any(32n, 49315)
    b7 : Listener & U32 <- listen_any(32n, 49316)
    b8 : Listener & U32 <- listen_any(32n, 49317)
    a : U32 <- case_two(b1)
    c : U32 <- case_two_bytes(b2)
    d : U32 <- case_big(b3)
    e : U32 <- case_truncated(b4)
    f : U32 <- case_bad_hex(b5)
    g : U32 <- case_trailer(b6)
    h : U32 <- case_head(b7)
    i : U32 <- case_both(b8)
    +total : U32 = (a + c + d + e + f + g + h + i : U32)
    w : Unit <- IO.print(U32.show(total))
    return w

#|8
