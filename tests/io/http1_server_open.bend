# io (http1_server_open): the TASK-081 open server lane (loop.pre.open
# feeding server.open) of lib/http1.bend, driven directly, no facade in
# the path. Seven cases,
# one connection each: cases 1-6 over plaintext TCP, case 7 over the
# module's own secure twin with the test cert:
#   1. upgrade_101 ....... a GET with upgrade headers plus extra bytes:
#                          the loop answers 101 (the head keeps
#                          Connection and Upgrade), ~K receives the
#                          socket and the rest, and echoes the rest
#                          through the lent socket.
#   2. refuse_rejoin ...... the handler answers 200, never 101: the
#                          answer rides the normal respond and the
#                          connection rejoins loop.server; two GETs on
#                          one socket, two 200s. The side rides
#                          server.open.once, the named TCP accept.
#   3. head_431 ........... a head past the 16384-byte cap: the open
#                          loop's own head reader answers 431 and
#                          closes.
#   4. bad_101_500 ........ a handler 101 with a CR/LF inside a header
#                          value: the render gate answers a bare 500,
#                          and the split marker never reaches the wire.
#   5. chunked_101 ........ a chunked POST that ends at its terminator:
#                          the loop decodes the body, ~H answers 101 on
#                          the exact decoded body, ~K answers a fixed
#                          marker through the lent socket.
#   6. chunked_trail_400 .. one byte past the chunked terminator in the
#                          same buffer: the shared chunk_step grammar
#                          answers one single 400, then EOF.
#   7. secure_101 ......... the same upgrade of case 1 through
#                          server.open.once_secure and the TLS triple:
#                          the 101 head, the rest to ~K and the echo
#                          back, all over the secure accept.
# Cases 1, 3, 4, 5 and 6 ride the public alias (the exact call shape the
# wsm lane makes); case 2 rides server.open.once and case 7 rides its
# secure twin.
# Golden 7.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/http1.bend as HTTP1
import ../../lib/http.bend as HTTP

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# Scoring: one marker, or one marker the raw must NOT carry.
def hit(r: Result<&1, &1, U32 & String, String>, +want: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+raw}:
      b2u(String.contains(raw, want))

def hit_not(r: Result<&1, &1, U32 & String, String>, +want: String, +never: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+raw}:
      U32.mul(b2u(String.contains(raw, want)), b2u(Bool.not(String.contains(raw, never))))

# The 101 head markers plus the echo marker, all from one match, so the
# affine read result is consumed once (the render keeps Connection and
# Upgrade on the 101 head).
def hit_101_rest(r: Result<&1, &1, U32 & String, String>, +want: String) -> U32 & U32:
  match r:
    case Fail{e}:
      (0, 0)
    case Done{+raw}:
      (U32.mul(b2u(String.contains(raw, "HTTP/1.1 101")),
        U32.mul(b2u(String.contains(raw, "Upgrade: websocket")),
          U32.mul(b2u(String.contains(raw, "Connection: Upgrade")),
            b2u(String.contains(raw, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="))))),
        b2u(String.contains(raw, want)))

# Cases 1, 3 and 6 handler: answers the upgrade 101. Case 3 never calls
# it (the 431 refuses first) and case 6 never calls it either (the chunk
# grammar refuses the trailing byte first).
def up_h(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{101, [HTTP.Hdr{"Upgrade", "websocket"}, HTTP.Hdr{"Connection", "Upgrade"}, HTTP.Hdr{"Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="}], Nil{}})

# Case 2 handler: never upgrades, so every answer rejoins the keep-alive
# loop.
def refuse_h(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, Nil{}})

# Case 4 handler: the response-splitting shape inside a 101 header value.
def bad_h(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{101, [HTTP.Hdr{"x-echo", "v\r\nx-split: 1"}], Nil{}})

# Case 5's answer on the decoded body check, one def so the match
# scrutinizes a parameter, not a computed value.
def up_chunk_ok(ok: Bool) -> IO(HTTP.Response):
  match ok:
    case True{}:
      IO.pure(HTTP.Response, HTTP.Response{101, [HTTP.Hdr{"Upgrade", "websocket"}, HTTP.Hdr{"Connection", "Upgrade"}, HTTP.Hdr{"Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="}], Nil{}})
    case False{}:
      IO.pure(HTTP.Response, HTTP.Response{500, Nil{}, Nil{}})

# Case 5 handler: 101 only on the exact decoded body, so the answer pins
# the chunked decode through the whole ladder.
def up_chunk_h(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      up_chunk_ok(String.eq(HTTP.x_bytes_str(body), "Wikipedia"))

# The ~K passed to every side but case 5's; only case 1 calls it (the
# other sides never answer a 101 with a rest). It proves both deliveries
# at once by echoing the rest bytes back through the lent socket, then
# closing. A failed send still closes: the send error already ended the
# lane's half.
def k_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s2, _r) = sent
  Socket.close(s2)

def k_echo(sock: Socket, rest: List<&2, U32>) -> IO(Unit):
  do IO<Unit>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, HTTP.x_bytes_str(rest))
    k_sent(sent)

# The ~K of case 5: the chunked request ends at its terminator, so the
# rest is empty. K answers a fixed marker so the client read proves the
# call, then closes.
def k_ok(sock: Socket, rest: List<&2, U32>) -> IO(Unit):
  do IO<Unit>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, "k-ok")
    k_sent(sent)

# Request texts.
def req_up() -> String:
  "GET /chat HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nrest-bytes"

def req_chunk_up() -> String:
  "POST /chat HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\n\r\n"

# Case 6: one byte rides the buffer past the chunked terminator. The
# shared chunk_step grammar answers a single 400 (the fold answers the
# same, measured with a probe), so this case pins today's contract.
def req_chunk_trail() -> String:
  "POST /chat HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\n\r\nX"

@unsafe
def filler.go(+n: U32, +acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0:
      acc
    case _:
      filler.go((n - 1 : U32), 65 <> acc)

def filler(n: U32) -> String:
  HTTP.x_bytes_str(filler.go(n, Nil{}))

def req_big_head() -> String:
  "GET /a HTTP/1.1\r\nHost: a\r\nx-pad: " ++ filler(17000) ++ "\r\n\r\n"

# Server sides: accept here, then the entry under test. The alias side
# makes the exact call the wsm lane makes.
def alias_conn(~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(Unit):
  (l, r) = m
  match r:
    case Fail{e}:
      Listener.close(l)
    case Done{sock}:
      HTTP1.x_h1.srv.head_open(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, ~H, ~K, 0, (sock, Done{Nil{}}), Nil{}, 64n, False{})

def alias_side(~H: HTTP.Request -> IO(HTTP.Response), ~K: Socket -> List<&2, U32> -> IO(Unit), l: Listener) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    x : Unit <- alias_conn(~H, ~K, m)
    return Unit{}

# Case 2's side: the named accept entry of the open family.
def side_rejoin(l: Listener) -> IO(Unit):
  HTTP1.server.open.once(~refuse_h, ~k_echo, l)

# Case 7's ~K: the echo through the lent socket over the TLS triple,
# closed with tls_close (the handle is opaque).
def tls_k_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s2, _r) = sent
  TLS.tls_close(s2)

def tls_k_echo(sock: Socket, rest: List<&2, U32>) -> IO(Unit):
  do IO<Unit>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(sock, rest)
    tls_k_sent(sent)

# Case 7's side: the secure twin of the open family, over the test cert.
def side_secure(l: Listener) -> IO(Unit):
  HTTP1.server.open.once_secure(~up_h, ~tls_k_echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")

def side_up(l: Listener) -> IO(Unit):
  alias_side(~up_h, ~k_echo, l)

def side_bad(l: Listener) -> IO(Unit):
  alias_side(~bad_h, ~k_echo, l)

def side_chunk(l: Listener) -> IO(Unit):
  alias_side(~up_chunk_h, ~k_ok, l)

def side_trail(l: Listener) -> IO(Unit):
  alias_side(~up_h, ~k_echo, l)

# Client drives of cases 1 and 5: the head read, then the echo read (the
# echo can land in either read, so both score).
def up_read2(got2: Socket & Result<&1, &1, U32 & String, String>, scores: U32 & U32, +want: String) -> IO(U32):
  (s2, r2) = got2
  (one, in1) = scores
  +score : U32 = (one * U32.max(in1, hit(r2, want)) : U32)
  do IO<U32>:
    x : Unit <- Socket.close(s2)
    IO.pure(U32, score)

def up_read1(got1: Socket & Result<&1, &1, U32 & String, String>, +want: String) -> IO(U32):
  (s1, r1) = got1
  do IO<U32>:
    got2 : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s1, 16384)
    up_read2(got2, hit_101_rest(r1, want), want)

def up_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>, +want: String) -> IO(U32):
  (s1, r1) = sent
  match r1:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s1)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got1 : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s1, 16384)
        up_read1(got1, want)

def drive_101(sock: Socket, +req: String, +want: String) -> IO(U32):
  do IO<U32>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req)
    up_sent(sent, want)

def drive_case1(sock: Socket) -> IO(U32):
  drive_101(sock, req_up(), "rest-bytes")

def drive_case5(sock: Socket) -> IO(U32):
  drive_101(sock, req_chunk_up(), "k-ok")

# Client drive of case 7: the same raw upgrade over the TLS triple. One
# def converts the byte answer to text so the TCP scorers stay shared.
def bs_str(r: Result<&1, &1, U32 & String, List<&2, U32>>) -> Result<&1, &1, U32 & String, String>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{+bs}:
      Done{HTTP.x_bytes_str(bs)}

def tls_up_read2(got2: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, scores: U32 & U32, +want: String) -> IO(U32):
  (s2, r2) = got2
  (one, in1) = scores
  +score : U32 = (one * U32.max(in1, hit(bs_str(r2), want)) : U32)
  do IO<U32>:
    x : Unit <- TLS.tls_close(s2)
    IO.pure(U32, score)

def tls_up_read1(got1: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +want: String) -> IO(U32):
  (s1, r1) = got1
  do IO<U32>:
    got2 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s1, 16384)
    tls_up_read2(got2, hit_101_rest(bs_str(r1), want), want)

def tls_up_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>, +want: String) -> IO(U32):
  (s1, r1) = sent
  match r1:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s1)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got1 : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s1, 16384)
        tls_up_read1(got1, want)

def drive_case7(sock: Socket) -> IO(U32):
  do IO<U32>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(sock, HTTP.x_str_bytes(req_up()))
    tls_up_sent(sent, "rest-bytes")

# Client drive of case 6: one 400, then EOF (a second status line would
# be the double-400 the old buffered machine shipped).
def hit_one_400(r: Result<&1, &1, U32 & String, String>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+raw}:
      U32.mul(b2u(String.contains(raw, "HTTP/1.1 400")), b2u(Bool.not(String.contains(raw, "\r\n\r\nHTTP/1.1"))))

def hit_eof(r: Result<&1, &1, U32 & String, String>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+raw}:
      b2u(String.is_empty(raw))

def trail_read2(got2: Socket & Result<&1, &1, U32 & String, String>, +one: U32) -> IO(U32):
  (s2, r2) = got2
  +score : U32 = (one * hit_eof(r2) : U32)
  do IO<U32>:
    x : Unit <- Socket.close(s2)
    IO.pure(U32, score)

def trail_read1(got1: Socket & Result<&1, &1, U32 & String, String>) -> IO(U32):
  (s1, r1) = got1
  +one : U32 = hit_one_400(r1)
  do IO<U32>:
    got2 : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s1, 16384)
    trail_read2(got2, one)

def trail_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  (s1, r1) = sent
  match r1:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s1)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got1 : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s1, 16384)
        trail_read1(got1)

def drive_trail(sock: Socket) -> IO(U32):
  do IO<U32>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req_chunk_trail())
    trail_sent(sent)

# Client drive of case 2: the first answer, then the second GET on the
# same socket.
def rejoin_read2(got2: Socket & Result<&1, &1, U32 & String, String>, +one: U32) -> IO(U32):
  (s2, r2) = got2
  +score : U32 = (one * hit(r2, "HTTP/1.1 200") : U32)
  do IO<U32>:
    x : Unit <- Socket.close(s2)
    IO.pure(U32, score)

def rejoin_sent2(sent2: Socket & Result<&1, &1, U32 & String, Unit>, +one: U32) -> IO(U32):
  (s2, r2) = sent2
  match r2:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s2)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got2 : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s2, 16384)
        rejoin_read2(got2, one)

def rejoin_read1(got1: Socket & Result<&1, &1, U32 & String, String>) -> IO(U32):
  (s1, r1) = got1
  +one : U32 = hit(r1, "HTTP/1.1 200")
  do IO<U32>:
    sent2 : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(s1, "GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
    rejoin_sent2(sent2, one)

def rejoin_sent1(sent1: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  (s1, r1) = sent1
  match r1:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s1)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got1 : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s1, 16384)
        rejoin_read1(got1)

def drive_rejoin(sock: Socket) -> IO(U32):
  do IO<U32>:
    sent1 : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n")
    rejoin_sent1(sent1)

# Client drive of case 3: the 431 of the head cap.
def cap_read(got: Socket & Result<&1, &1, U32 & String, String>) -> IO(U32):
  (s, r) = got
  +score : U32 = hit(r, "HTTP/1.1 431")
  do IO<U32>:
    x : Unit <- Socket.close(s)
    IO.pure(U32, score)

def cap_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  (s1, r1) = sent
  match r1:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s1)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s1, 16384)
        cap_read(got)

def drive_431(sock: Socket) -> IO(U32):
  do IO<U32>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req_big_head())
    cap_sent(sent)

# Client drive of case 4: the bare 500, never the split.
def bad_read(got: Socket & Result<&1, &1, U32 & String, String>) -> IO(U32):
  (s, r) = got
  +score : U32 = hit_not(r, "HTTP/1.1 500", "x-split: 1")
  do IO<U32>:
    x : Unit <- Socket.close(s)
    IO.pure(U32, score)

def bad_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  (s1, r1) = sent
  match r1:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s1)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s1, 16384)
        bad_read(got)

def drive_bad(sock: Socket) -> IO(U32):
  do IO<U32>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, "GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
    bad_sent(sent)

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

# One case: fork the side, dial, drive the client ladder. The listen pair
# is passed whole and destructured at the top of the runner (a
# destructuring cannot follow a do bind).
def run_conn(~drive: Socket -> IO(U32), conn: Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      drive(sock)

def run_case(~side: Listener -> IO(Unit), ~drive: Socket -> IO(U32), b: Listener & U32) -> IO(U32):
  (l, p) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", p)
    run_conn(~drive, conn)

# The TLS runner: the client dials with no chain verify (the test cert
# is self-signed), the drive reads the TLS triple.
def run_case_tls(~side: Listener -> IO(Unit), ~drive: Socket -> IO(U32), b: Listener & U32) -> IO(U32):
  (l, p) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_noalpn_insecure("127.0.0.1", p)
    run_conn(~drive, conn)

def case_open(~side: Listener -> IO(Unit), ~drive: Socket -> IO(U32), +port: U32) -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(8n, port)
    run_case(~side, ~drive, b)

def case_open_tls(~side: Listener -> IO(Unit), ~drive: Socket -> IO(U32), +port: U32) -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(8n, port)
    run_case_tls(~side, ~drive, b)

def main() -> IO(U32):
  do IO<U32>:
    a : U32 <- case_open(~side_up, ~drive_case1, 20620)
    b : U32 <- case_open(~side_rejoin, ~drive_rejoin, 20621)
    c : U32 <- case_open(~side_up, ~drive_431, 20622)
    d : U32 <- case_open(~side_bad, ~drive_bad, 20623)
    e : U32 <- case_open(~side_chunk, ~drive_case5, 20624)
    f : U32 <- case_open(~side_trail, ~drive_trail, 20625)
    g : U32 <- case_open_tls(~side_secure, ~drive_case7, 20626)
    +total : U32 = (a + b + c + d + e + f + g : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|7
