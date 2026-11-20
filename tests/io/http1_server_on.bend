# io (http1_server_on): the TASK-081 accept-loop entries of
# lib/http1.bend, driven directly, no facade in the path. The once
# twins and the .conn arms have their own tests (http1_server_stream,
# http1_server_open, http1_client_stream); the loop entries own the
# re-accept, so every case drives two connections and scores the
# product: the second connection answers only if the loop accepted
# again. Four cases:
#   1. on_buffered ...... server.on: two GETs on two connections,
#                         two 200s (the buffered keep-alive loop).
#   2. on_stream ........ server.stream.on: two CL POSTs on two
#                         connections, two 200s (the stream loop).
#   3. on_open .......... server.open.on: two upgrades, each with the
#                         101 head and the rest echoed back (the
#                         wsm-ready lane).
#   4. on_open_secure ... server.open.on_secure: the same upgrade
#                         twice over the TLS triple.
# The forked loops never return, so main ends with IO.die (the
# http2_client_cres pattern).
# Golden 4.
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

# Scoring: one marker.
def hit(r: Result<&1, &1, U32 & String, String>, +want: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+raw}:
      b2u(String.contains(raw, want))

# The 101 head markers plus the echo marker, one match so the affine
# read result is consumed once (the same scorer of http1_server_open).
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

# Case 1 handler: answers 200, never upgrades.
def echo_h(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, Nil{}})

# Case 2 handler: the first data event answers the echo.
def sh_echo(ev: HTTP.SrvEv) -> HTTP.SrvOut:
  match ev:
    case HTTP.SrvReqHead{slot, head}:
      HTTP.Continue{}
    case HTTP.SrvReqData{slot, +chunk, fin}:
      HTTP.RespondEarly{HTTP.Response{200, Nil{}, chunk}}

# Cases 3 and 4 handler: answers the upgrade 101.
def up_h(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{101, [HTTP.Hdr{"Upgrade", "websocket"}, HTTP.Hdr{"Connection", "Upgrade"}, HTTP.Hdr{"Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="}], Nil{}})

# The ~K of case 3: echoes the rest through the lent socket, then
# closes. A failed send still closes: the send error already ended the
# lane's half.
def k_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s2, _r) = sent
  Socket.close(s2)

def k_echo(sock: Socket, rest: List<&2, U32>) -> IO(Unit):
  do IO<Unit>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, HTTP.x_bytes_str(rest))
    k_sent(sent)

# The ~K of case 4: the same echo over the TLS triple, closed with
# tls_close (the handle is opaque).
def tls_k_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s2, _r) = sent
  TLS.tls_close(s2)

def tls_k_echo(sock: Socket, rest: List<&2, U32>) -> IO(Unit):
  do IO<Unit>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(sock, rest)
    tls_k_sent(sent)

# Request texts.
def req_get() -> String:
  "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n"

def req_cl() -> String:
  "POST /up HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\nhi"

def req_up() -> String:
  "GET /chat HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nrest-bytes"

# The one-answer ladder of cases 1 and 2: send, read, close.
def got_hit(got: Socket & Result<&1, &1, U32 & String, String>, +want: String) -> IO(U32):
  (s, r) = got
  do IO<U32>:
    x : Unit <- Socket.close(s)
    IO.pure(U32, hit(r, want))

def sent_hit(sent: Socket & Result<&1, &1, U32 & String, Unit>, +want: String) -> IO(U32):
  (s1, r1) = sent
  match r1:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s1)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s1, 16384)
        got_hit(got, want)

def drive_one(sock: Socket, +req: String, +want: String) -> IO(U32):
  do IO<U32>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req)
    sent_hit(sent, want)

# The 101 ladder of case 3: the head read, then the echo read (the echo
# can land in either read, so both score).
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

# Case 4's ladder: the byte answer converts to text so the TCP scorers
# stay shared.
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

def drive_tls(sock: Socket, +req: String, +want: String) -> IO(U32):
  do IO<U32>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(sock, HTTP.x_str_bytes(req))
    tls_up_sent(sent, want)

# The drives pick the request and the marker for each case.
def drive_get(sock: Socket) -> IO(U32):
  drive_one(sock, req_get(), "HTTP/1.1 200")

def drive_cl(sock: Socket) -> IO(U32):
  drive_one(sock, req_cl(), "HTTP/1.1 200")

def drive_up(sock: Socket) -> IO(U32):
  drive_101(sock, req_up(), "rest-bytes")

def drive_up_tls(sock: Socket) -> IO(U32):
  drive_tls(sock, req_up(), "rest-bytes")

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

# One connection: dial, then the drive ladder.
def run_conn(~drive: Socket -> IO(U32), conn: Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      drive(sock)

# Two connections through the forked loop: the product scores only when
# both answer, so the second pins the re-accept. The port rides as an
# affine param: the pair owns the listener, the caller owns the port.
def run_two(~side: Listener -> IO(Unit), ~drive: Socket -> IO(U32), b: Listener & U32, +port: U32) -> IO(U32):
  (l, _p) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, side(l))
    c1 : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", port)
    s1 : U32 <- run_conn(~drive, c1)
    c2 : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", port)
    s2 : U32 <- run_conn(~drive, c2)
    IO.pure(U32, (s1 * s2 : U32))

def run_two_tls(~side: Listener -> IO(Unit), ~drive: Socket -> IO(U32), b: Listener & U32, +port: U32) -> IO(U32):
  (l, _p) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, side(l))
    c1 : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_noalpn_insecure("127.0.0.1", port)
    s1 : U32 <- run_conn(~drive, c1)
    c2 : Result<&1, &1, U32 & String, Socket> <- TLS.tls_connect_noalpn_insecure("127.0.0.1", port)
    s2 : U32 <- run_conn(~drive, c2)
    IO.pure(U32, (s1 * s2 : U32))

# The sides: one loop entry each.
def side_buffered(l: Listener) -> IO(Unit):
  HTTP1.server.on(~echo_h, l)

def side_stream(l: Listener) -> IO(Unit):
  HTTP1.server.stream.on(~sh_echo, l)

def side_open(l: Listener) -> IO(Unit):
  HTTP1.server.open.on(~up_h, ~k_echo, l)

def side_open_secure(l: Listener) -> IO(Unit):
  HTTP1.server.open.on_secure(~up_h, ~tls_k_echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")

def case_on(~side: Listener -> IO(Unit), ~drive: Socket -> IO(U32), +port: U32) -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(8n, port)
    run_two(~side, ~drive, b, port)

def case_on_tls(~side: Listener -> IO(Unit), ~drive: Socket -> IO(U32), +port: U32) -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(8n, port)
    run_two_tls(~side, ~drive, b, port)

def main() -> IO(U32):
  do IO<U32>:
    a : U32 <- case_on(~side_buffered, ~drive_get, 20630)
    b : U32 <- case_on(~side_stream, ~drive_cl, 20631)
    c : U32 <- case_on(~side_open, ~drive_up, 20632)
    d : U32 <- case_on_tls(~side_open_secure, ~drive_up_tls, 20633)
    +total : U32 = (a + b + c + d : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|4
