# httpx (httpx_h1_upgrade_client): H1 upgrade on the client lane.
#
# Pure renderer vectors: the upgrade flag keeps the handshake's own
# headers (Upgrade/Connection, case-insensitively) and drops the
# Content-Length of an empty body; upgrade=False keeps the old bytes.
# Canned-peer round trip over plain TCP through x_h1.cli.exch.open:
# the peer answers 101 + headers + one frame in a single write, and the
# client must come back with status 101, the frame bytes as rest, and a
# socket that still works (one byte down, the same byte back).
# A second peer answers 200: the open chain must refuse it fail-closed
# with 502 "upgrade without 101" without reading a body.
# A third peer answers the handshake with more than 70 KB and no blank
# line anywhere: past the 64 KiB client budget the read answers Fail
# 413, the code of its fuel floor, and keeps the process alive.
# TASK-081 Phase 4.5 raised the client budget from 16 KiB to 64 KiB
# (the H2 twin's block budget; the RFC sets no limit, node caps at
# 16 KiB, Chrome at 256 KiB) and made every walk of the head
# tail-safe. The three last cases pin the new contract: a valid 101
# head of ~24 KiB parses (the window the old budget refused), a valid
# head of 8000 short lines (~56 KiB) parses through the tail fold, and
# one line of 20 KB fails closed with 400 "line too long" (the
# per-line gate keeps every Base walk on one line under the stack
# ceiling; nginx and Apache cap a line at 8 KiB).
# The named vectors of TASK-081 Phase 4 close the family: client.open
# dials TCP and answers the socket, the response and the rest in one
# triple; the cap case rides it (the rewrap closes on the 413 path),
# the plain round scores 101 + rest + echo through it,
# client.open_insecure runs the same round over the module's own
# secure open server (the echo through the lent TLS handle proves the
# triple carries the TLS transport), and client.open_secure refuses
# the self-signed test cert with 614 before any byte.
# Golden 25 = 3 (renderer) + 3 (101 + rest + echo) + 1 (502) + 3 (the
# same three checks behind a 100 that must be discarded) + 1 (head cap)
# + 3 (plain vector) + 3 (insecure vector) + 1 (verified refuse)
# + 3 (reopened window) + 3 (many lines) + 1 (line gate).
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

def up_hs() -> List<&2, HTTP.Hdr>:
  [HTTP.Hdr{"Upgrade", "websocket"}, HTTP.Hdr{"Connection", "Upgrade"}, HTTP.Hdr{"Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="}, HTTP.Hdr{"Sec-WebSocket-Version", "13"}]

def rv.go(r: Result<&1, &1, U32 & String, List<&2, U32>>, +want: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+bs}:
      HTTP.x_eq(bs, HTTP.x_str_bytes(want))

# upgrade=True keeps the handshake headers and claims no Content-Length.
def rv.up() -> U32:
  rv.go(HTTP1.x_h1.render_req.go(True{}, False{}, "GET", "/chat", "h", 80, up_hs(), Nil{}), "GET /chat HTTP/1.1\r\nHost: h:80\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")

# upgrade=False is the old bytes: handshake headers stripped, Length 0.
def rv.old() -> U32:
  rv.go(HTTP1.x_h1.render_req.go(False{}, False{}, "GET", "/chat", "h", 80, up_hs(), Nil{}), "GET /chat HTTP/1.1\r\nHost: h:80\r\nContent-Length: 0\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")

# upgrade=True with a body keeps the headers and still counts the bytes.
def rv.body() -> U32:
  rv.go(HTTP1.x_h1.render_req.go(True{}, False{}, "GET", "/chat", "h", 80, up_hs(), [104, 105]), "GET /chat HTTP/1.1\r\nHost: h:80\r\nContent-Length: 2\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\nhi")

def rv.all() -> U32:
  (rv.up() + rv.old() + rv.body() : U32)

# One text frame "hi": what the peer parks past the head, and what rest
# must be, byte for byte.
def frame_want() -> List<&2, U32>:
  [129, 2, 104, 105]

def canned101() -> List<&2, U32>:
  List.append(&2, U32, HTTP.x_str_bytes("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"), frame_want())

# A 100 Continue before the 101 (RFC 9110 section 15.2): the client must
# discard the interim head and read the next one. The plain lane always
# did; TASK-055 Phase 6b gives the upgrade lane the same rule, because one
# chain now serves both.
def canned_info101() -> List<&2, U32>:
  List.append(&2, U32, HTTP.x_str_bytes("HTTP/1.1 100 Continue\r\n\r\n"), canned101())

def canned200() -> List<&2, U32>:
  HTTP.x_str_bytes("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")

# The over-long head: a status line plus 60000 bytes, no blank line
# anywhere. Tail builder, because List.replicate is not tail-recursive
# (the measured lesson of the bench file).
def pad(n: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      pad(p, 65 <> acc)

def big_head() -> List<&2, U32>:
  List.append(&2, U32, HTTP.x_str_bytes("HTTP/1.1 101 Switching Protocols\r\nX-Pad: "), pad(70000n, Nil{}))

# The line builder of the valid big heads: n copies of one short line,
# pushed in final order (x_cat un-reverses the whole at the end).
def many_pad(n: Nat, +line: String, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      many_pad(p, line, HTTP.x_rev_push(HTTP.x_str_bytes(line), acc))

# The reopened window: a valid 101 of ~24 KiB, past the old 16 KiB
# budget and far under the 64 KiB one, every line short.
def reopen_head() -> List<&2, U32>:
  HTTP.x_cat(HTTP.x_rev_push([129, 2, 104, 105], HTTP.x_rev_push(HTTP.x_str_bytes("\r\n"), many_pad(2000n, "x-pad: aaaa\r\n", HTTP.x_rev_push(HTTP.x_str_bytes("HTTP/1.1 101 Switching Protocols\r\n"), Nil{})))))

# The many-lines head: 8000 short lines, ~56 KiB, valid, under the
# budget. The parse-depth pin: the fold answers without a fault.
def many_head() -> List<&2, U32>:
  HTTP.x_cat(HTTP.x_rev_push([129, 2, 104, 105], HTTP.x_rev_push(HTTP.x_str_bytes("\r\n"), many_pad(8000n, "a: bb\r\n", HTTP.x_rev_push(HTTP.x_str_bytes("HTTP/1.1 101 Switching Protocols\r\n"), Nil{})))))

# One line of 20 KB: the per-line gate answers 400 before any Base
# walk on the line.
def line_head() -> List<&2, U32>:
  HTTP.x_cat(HTTP.x_rev_push(HTTP.x_str_bytes("\r\n\r\n"), pad(20000n, HTTP.x_rev_push(HTTP.x_str_bytes("x-long: "), HTTP.x_rev_push(HTTP.x_str_bytes("HTTP/1.1 101 Switching Protocols\r\n"), Nil{})))))

def cli_echo_got(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: U32) -> IO(U32):
  (s, r) = got
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        IO.pure(U32, acc)
    case Done{+part}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        IO.pure(U32, (acc + HTTP.x_eq(part, [7]) : U32))

def cli_echo_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>, +acc: U32) -> IO(U32):
  (s, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        IO.pure(U32, acc)
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TCP.recv_bytes(s, 16)
        cli_echo_got(got, acc)

def cli_echofy(sock: Socket, +acc: U32) -> IO(U32):
  do IO<U32>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send_bytes(sock, [7])
    cli_echo_sent(sent, acc)

def cli_score(out: Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>) -> IO(U32):
  (s2, r2) = out
  match r2:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s2)
        IO.pure(U32, 0)
    case Done{pr}:
      (resp, rest) = pr
      match resp:
        case HTTP.Response{+status, +headers, +body}:
          +acc : U32 = (b2u(U32.is_eq(status, 101)) + HTTP.x_eq(rest, frame_want()) : U32)
          cli_echofy(s2, acc)

def cli_round(conn: Result<&1, &1, U32 & String, Socket>, +port: U32) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        out : Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>> <- HTTP1.x_h1.cli.exch.open(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, sock, "127.0.0.1", port, "GET", "/chat", up_hs(), Nil{})
        cli_score(out)

# The peer echoes the one post-handshake byte, proving the socket the
# triple handed over is live in both directions.
def peer_echoed(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  (s2, r2) = sent
  do IO<U32>:
    x : Unit <- Socket.close(s2)
    IO.pure(U32, 0)

def peer_echo(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(U32):
  (s, r) = got
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        IO.pure(U32, 0)
    case Done{+part}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send_bytes(s, part)
        peer_echoed(sent)

def peer_after(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  (s, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TCP.recv_bytes(s, 16)
        peer_echo(got)

# Drain the handshake request before answering: the first recv carries
# the client's head, not the post-handshake byte — echoing it would
# answer the wrong bytes and desync the round trip. One phased def
# (the dialect forbids the drain/drained/found mutual trio).
@unsafe
def peer_drain(phase: U32, got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: List<&2, U32>, fuel: Nat, found: Bool, +head: List<&2, U32>) -> IO(U32):
  match phase:
    case 0:
      (s0, r0) = got
      match fuel:
        case 0n:
          do IO<U32>:
            x : Unit <- Socket.close(s0)
            IO.pure(U32, 0)
        case 1n+f:
          do IO<U32>:
            r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TCP.recv_bytes(s0, 16384)
            peer_drain(1, r, acc, f, False{}, head)
    case 1:
      (s1, r1) = got
      match r1:
        case Fail{e}:
          do IO<U32>:
            x : Unit <- Socket.close(s1)
            IO.pure(U32, 0)
        case Done{+part}:
          +acc2 : List<&2, U32> = List.append(&2, U32, acc, part)
          peer_drain(2, (s1, Done{Nil{}}), acc2, fuel, HTTP1.x_h1.split_found(HTTP1.x_h1.split(acc2)), head)
    case 2:
      (s2, r2) = got
      match found:
        case True{}:
          do IO<U32>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send_bytes(s2, head)
            peer_after(sent)
        case False{}:
          peer_drain(0, (s2, Done{Nil{}}), acc, fuel, False{}, head)
    case _:
      (s9, r9) = got
      do IO<U32>:
        x : Unit <- Socket.close(s9)
        IO.pure(U32, 0)

def peer_open(conn: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  (l, r) = conn
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      peer_drain(0, (sock, Done{Nil{}}), Nil{}, 64n, False{}, canned101())

def peer_side(l: Listener) -> IO(U32):
  do IO<U32>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    peer_open(m)

def peer_open_info(conn: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  (l, r) = conn
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      peer_drain(0, (sock, Done{Nil{}}), Nil{}, 64n, False{}, canned_info101())

def peer_side_info(l: Listener) -> IO(U32):
  do IO<U32>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    peer_open_info(m)

def run_info(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, peer_side_info(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", port)
    cli_round(conn, port)

def run_open(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, peer_side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", port)
    cli_round(conn, port)

def cli_reject(out: Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>>) -> IO(U32):
  (s2, r2) = out
  match r2:
    case Fail{e}:
      (code, msg) = e
      do IO<U32>:
        x : Unit <- Socket.close(s2)
        IO.pure(U32, b2u(U32.is_eq(code, 502)))
    case Done{pr}:
      (resp, rest) = pr
      do IO<U32>:
        x : Unit <- Socket.close(s2)
        IO.pure(U32, 0)

def cli_round_reject(conn: Result<&1, &1, U32 & String, Socket>, +port: U32) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        out : Socket & Result<&1, &1, U32 & String, HTTP.Response & List<&2, U32>> <- HTTP1.x_h1.cli.exch.open(~TCP.recv_bytes, ~TCP.send_bytes, ~Socket.close, sock, "127.0.0.1", port, "GET", "/chat", up_hs(), Nil{})
        cli_reject(out)

def peer_denied(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  (s2, r2) = sent
  do IO<U32>:
    x : Unit <- Socket.close(s2)
    IO.pure(U32, 0)

def peer_deny(conn: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(U32):
  (l, r) = conn
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send_bytes(sock, canned200())
        peer_denied(sent)

def peer_side_deny(l: Listener) -> IO(U32):
  do IO<U32>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    peer_deny(m)

def run_reject(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, peer_side_deny(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", port)
    cli_round_reject(conn, port)

# The cap case rides the bare vector: the over-long head answers the
# 413 of the fuel floor (TASK-081 Phase 4), not the memory fault the
# deep append answered before the cap. The vector's rewrap closes the
# socket on the Fail path, so the score only reads the code.
def peer_open_blob(conn: Listener & Result<&1, &1, U32 & String, Socket>, +blob: List<&2, U32>) -> IO(U32):
  (l, r) = conn
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      peer_drain(0, (sock, Done{Nil{}}), Nil{}, 64n, False{}, blob)

def peer_side_blob(l: Listener, +blob: List<&2, U32>) -> IO(U32):
  do IO<U32>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    peer_open_blob(m, blob)

def peer_side_big(l: Listener) -> IO(U32):
  peer_side_blob(l, big_head())

def cli_cap(r: Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>) -> IO(U32):
  match r:
    case Fail{e}:
      (code, msg) = e
      IO.pure(U32, b2u(U32.is_eq(code, 413)))
    case Done{pr}:
      (s2, _resp, _rest) = pr
      do IO<U32>:
        x : Unit <- Socket.close(s2)
        IO.pure(U32, 0)

def run_cap(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, peer_side_big(l))
    r : Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>> <- HTTP1.client.open("127.0.0.1", port, "GET", "/chat", up_hs(), Nil{})
    cli_cap(r)

# The bare vector's Done path: the canned 101 peer, the triple scored
# (101, rest, echo) through the dialed entry.
def vec_score(r: Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>) -> IO(U32):
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{pr}:
      (s, resp, rest) = pr
      match resp:
        case HTTP.Response{+status, +headers, +body}:
          +acc : U32 = (b2u(U32.is_eq(status, 101)) + HTTP.x_eq(rest, frame_want()) : U32)
          cli_echofy(s, acc)

def run_vec_plain(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, peer_side(l))
    r : Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>> <- HTTP1.client.open("127.0.0.1", port, "GET", "/chat", up_hs(), Nil{})
    vec_score(r)

# The TLS open server for the vector twins: the handler answers the
# upgrade 101, the ~K echoes the rest through the lent TLS handle.
def up_h(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{101, [HTTP.Hdr{"Upgrade", "websocket"}, HTTP.Hdr{"Connection", "Upgrade"}, HTTP.Hdr{"Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="}], Nil{}})

def tls_k_fin(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s3, _sr) = sent
  TLS.tls_close(s3)

def tls_k_after(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Unit):
  (s, r) = got
  match r:
    case Fail{e}:
      TLS.tls_close(s)
    case Done{+part}:
      do IO<Unit>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(s, part)
        tls_k_fin(sent)

def tls_k_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s2, _r) = sent
  do IO<Unit>:
    got : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s2, 16)
    tls_k_after(got)

def tls_k_echo(sock: Socket, rest: List<&2, U32>) -> IO(Unit):
  do IO<Unit>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(sock, frame_want())
    tls_k_sent(sent)

def side_vec_tls(l: Listener) -> IO(Unit):
  HTTP1.server.open.once_secure(~up_h, ~tls_k_echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")

# The echo through the lent handle: the triple's socket must be the TLS
# handle, so the byte goes out and comes back through the TLS triple.
def tls_echo_got(got: Socket & Result<&1, &1, U32 & String, List<&2, U32>>, +acc: U32) -> IO(U32):
  (s, r) = got
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s)
        IO.pure(U32, acc)
    case Done{+part}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s)
        IO.pure(U32, (acc + HTTP.x_eq(part, [7]) : U32))

def tls_echo_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>, +acc: U32) -> IO(U32):
  (s, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s)
        IO.pure(U32, acc)
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TLS.tls_recv_bytes(s, 16)
        tls_echo_got(got, acc)

def tls_echofy(sock: Socket, +acc: U32) -> IO(U32):
  do IO<U32>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- TLS.tls_send_bytes(sock, [7])
    tls_echo_sent(sent, acc)

# The insecure vector: the same 101 + rest + echo through the TLS dial
# without chain verify, against the module's own secure open server.
def vec_tls_score(r: Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>) -> IO(U32):
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{pr}:
      (s, resp, rest) = pr
      match resp:
        case HTTP.Response{+status, +headers, +body}:
          +acc : U32 = (b2u(U32.is_eq(status, 101)) + HTTP.x_eq(rest, frame_want()) : U32)
          tls_echofy(s, acc)

def run_vec_insecure(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(Unit) <- IO.fork(Unit, side_vec_tls(l))
    r : Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>> <- HTTP1.client.open_insecure("127.0.0.1", port, "GET", "/chat", up_hs(), Nil{})
    vec_tls_score(r)

# The verified twin refuses the self-signed test cert with 614, before
# any byte leaves the dial.
def vec_refuse(r: Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>) -> IO(U32):
  match r:
    case Fail{e}:
      (code, msg) = e
      IO.pure(U32, b2u(U32.is_eq(code, 614)))
    case Done{pr}:
      (s2, _resp, _rest) = pr
      do IO<U32>:
        x : Unit <- TLS.tls_close(s2)
        IO.pure(U32, 0)

def run_vec_refuse(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(Unit) <- IO.fork(Unit, side_vec_tls(l))
    r : Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>> <- HTTP1.client.open_secure("127.0.0.1", port, "GET", "/chat", up_hs(), Nil{})
    vec_refuse(r)

# The three budget cases (TASK-081 Phase 4.5), all through the bare
# vector: the reopened window, the many-lines fold, the line gate.
def vec_fail(r: Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>>, +want: U32) -> IO(U32):
  match r:
    case Fail{e}:
      (code, msg) = e
      IO.pure(U32, b2u(U32.is_eq(code, want)))
    case Done{pr}:
      (s2, _resp, _rest) = pr
      do IO<U32>:
        x : Unit <- Socket.close(s2)
        IO.pure(U32, 0)

def run_vec_reopen(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, peer_side_blob(l, reopen_head()))
    r : Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>> <- HTTP1.client.open("127.0.0.1", port, "GET", "/chat", up_hs(), Nil{})
    vec_score(r)

def run_vec_many(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, peer_side_blob(l, many_head()))
    r : Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>> <- HTTP1.client.open("127.0.0.1", port, "GET", "/chat", up_hs(), Nil{})
    vec_score(r)

def run_vec_line(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    c : Chan(U32) <- IO.fork(U32, peer_side_blob(l, line_head()))
    r : Result<&1, &1, U32 & String, Socket & HTTP.Response & List<&2, U32>> <- HTTP1.client.open("127.0.0.1", port, "GET", "/chat", up_hs(), Nil{})
    vec_fail(r, 400)

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
    +pure : U32 = rv.all()
    b1 : Listener & U32 <- listen_any(32n, 18520)
    +up : U32 <- run_open(b1)
    b2 : Listener & U32 <- listen_any(32n, 18521)
    +rej : U32 <- run_reject(b2)
    b3 : Listener & U32 <- listen_any(32n, 18522)
    +inf : U32 <- run_info(b3)
    b4 : Listener & U32 <- listen_any(32n, 18523)
    +cap : U32 <- run_cap(b4)
    b5 : Listener & U32 <- listen_any(32n, 18524)
    +vec : U32 <- run_vec_plain(b5)
    b6 : Listener & U32 <- listen_any(32n, 18525)
    +vtls : U32 <- run_vec_insecure(b6)
    b7 : Listener & U32 <- listen_any(32n, 18526)
    +vref : U32 <- run_vec_refuse(b7)
    b8 : Listener & U32 <- listen_any(32n, 18527)
    +vreo : U32 <- run_vec_reopen(b8)
    b9 : Listener & U32 <- listen_any(32n, 18528)
    +vmany : U32 <- run_vec_many(b9)
    b10 : Listener & U32 <- listen_any(32n, 18529)
    +vline : U32 <- run_vec_line(b10)
    +total : U32 = (pure + up + rej + inf + cap + vec + vtls + vref + vreo + vmany + vline : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|25
