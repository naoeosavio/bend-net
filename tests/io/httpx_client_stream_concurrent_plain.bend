# io (httpx_client_stream_concurrent_plain): the client's plaintext
# concurrent streaming lane (task-054 phase 4) plus the server alias
# server.stream_concurrent_plain.
#
# Five claims, one point each:
#   * against the library alias server, two cleartext requests travel at
#     the same time: /echo answers 200 with the 5-byte body, /cancel
#     answers 418 at the head and the handler cancels that connection.
#     The batch answers the bytes and the finished streams of the
#     siblings: 5 and 1.
#   * against a canned peer that answers only when both requests have
#     arrived, two requests answer 200 with 5 bytes each: 10 and 2. A
#     client that dials one connection at a time deadlocks, so this
#     claim proves that the dials overlap (bounded by the check.sh
#     timeout).
#   * an empty request list answers (0, 0) with no dial.
#   * a canned peer that closes both connections after reading the
#     requests fails the batch: 400 "eof", the error of the first
#     connection in request order.
#   * a list with one invalid request answers 400 "bad request" and no
#     connection opens. The peer of this claim reads one connection and
#     closes it, so a dial answers 400 "eof" instead: the claim fails by
#     value, not by a hang.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18591

def HOST() -> String:
  "127.0.0.1"

# The status /cancel answers, and the status the handler cancels on.
def CANCEL_STATUS() -> U32:
  418

def TWO_HELLO() -> U32:
  10

def ONE_HELLO() -> U32:
  5

def TWO_FINS() -> U32:
  2

def ONE_FIN() -> U32:
  1

# Byte counts of a canned response: the 5-byte body of peer_resp.
def PEER_HELLO() -> U32:
  5

def RECV_MAX() -> U32:
  4096

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def eq2(p: U32 & U32, want_total: U32, want_fins: U32) -> U32:
  match p:
    case (total, fins):
      b2u(Bool.and(U32.is_eq(total, want_total), U32.is_eq(fins, want_fins)))

# Server: /cancel answers at the head with no body, every other path
# buffers and echoes its first chunk. The Bool of the path test rides an
# argument, because a match cannot scrutinize a call.
def srv_head_act(is_cancel: Bool) -> HTTP.SrvOut:
  match is_cancel:
    case True{}:
      HTTP.RespondEarly{HTTP.Response{CANCEL_STATUS(), Nil{}, Nil{}}}
    case False{}:
      HTTP.Continue{}

def srv_head(path: String) -> HTTP.SrvOut:
  srv_head_act(String.eq(path, "/cancel"))

def srv_data(chunk: List<&2, U32>) -> HTTP.SrvOut:
  HTTP.RespondEarly{HTTP.Response{200, Nil{}, chunk}}

def h_srv(ev: HTTP.SrvEv) -> HTTP.SrvOut:
  match ev:
    case HTTP.SrvReqHead{slot, head}:
      match head:
        case HTTP.ReqHead{+method, +path, +headers}:
          srv_head(path)
    case HTTP.SrvReqData{slot, +chunk, fin}:
      srv_data(chunk)

# Client: the status of the response head is the only key this pure
# handler has. H1 carries no slot, and a template lane cannot take one
# (discovery C13).
def h_cli_status(status: U32) -> HTTP.StreamOut:
  match status:
    case 418:
      HTTP.StreamCancel{}
    case _:
      HTTP.StreamContinue{}

def h_cli(ev: HTTP.StreamEv) -> HTTP.StreamOut:
  match ev:
    case HTTP.StreamHead{head}:
      match head:
        case HTTP.Head{+status, +headers}:
          h_cli_status(status)
    case HTTP.StreamData{chunk, fin}:
      HTTP.StreamContinue{}

def req_echo() -> HTTP.Request:
  HTTP.Request{"POST", "/echo", Nil{}, HTTP.x_str_bytes("hello")}

def req_cancel() -> HTTP.Request:
  HTTP.Request{"POST", "/cancel", Nil{}, HTTP.x_str_bytes("x")}

def reqs_two() -> List<&2, HTTP.Request>:
  [req_echo(), req_cancel()]

def reqs_peer() -> List<&2, HTTP.Request>:
  [req_echo(), req_echo()]

def reqs_empty() -> List<&2, HTTP.Request>:
  Nil{}

# A path with a space is not a valid request path (client.on.valid_path).
def req_bad() -> HTTP.Request:
  HTTP.Request{"POST", "/bad path", Nil{}, Nil{}}

def reqs_mixed() -> List<&2, HTTP.Request>:
  [req_echo(), req_bad()]

# A free port at or above the asked one, walked upward while a bind fails.
def listen_retry(port: U32, r: Result<&1, &1, (U32 & String), Listener>, rest: IO(Listener & U32)) -> IO(Listener & U32):
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
        r : Result<&1, &1, (U32 & String), Listener> <- TCP.listen(port)
        listen_retry(port, r, rest)

# A canned 200 with a 5-byte body, then close.
def peer_resp() -> List<&2, U32>:
  HTTP.x_str_bytes("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")

# The peer dies on its own failure: a broken peer is a broken test, and a
# silent one would make the client hang instead of failing.
def peer_accept_go(m: Listener & Result<&1, &1, U32 & String, Socket>) -> IO(Listener & Socket):
  (l, r) = m
  match r:
    case Fail{e}:
      IO.die(Listener & Socket, 1, "peer accept failed")
    case Done{sock}:
      IO.pure(Listener & Socket, (l, sock))

def peer_accept(l: Listener) -> IO(Listener & Socket):
  do IO<Listener & Socket>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    peer_accept_go(m)

def peer_read_go(r: Socket & Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Socket):
  (s, got) = r
  match got:
    case Fail{e}:
      IO.die(Socket, 1, "peer recv failed")
    case Done{bytes}:
      IO.pure(Socket, s)

def peer_read(sock: Socket) -> IO(Socket):
  do IO<Socket>:
    r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- TCP.recv_bytes(sock, RECV_MAX())
    peer_read_go(r)

def peer_send_go(r: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Unit):
  (s, sent) = r
  match sent:
    case Fail{e}:
      IO.die(Unit, 1, "peer send failed")
    case Done{u}:
      Socket.close(s)

def peer_answer(sock: Socket) -> IO(Unit):
  do IO<Unit>:
    r : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send_bytes(sock, peer_resp())
    peer_send_go(r)

# One request of each connection, then one action for both: 0 answers
# both, 1 closes both. The peer reads both requests before either action,
# so it answers only after the two dials arrived.
def peer_pair_act(kind: U32, one: Socket, two: Socket) -> IO(Unit):
  match kind:
    case 0:
      do IO<Unit>:
        x : Unit <- peer_answer(one)
        y : Unit <- peer_answer(two)
        return Unit{}
    case _:
      do IO<Unit>:
        x : Unit <- Socket.close(one)
        y : Unit <- Socket.close(two)
        return Unit{}

def peer_pair_tail(one: Socket, b2: Listener & Socket, kind: U32) -> IO(Unit):
  (l2, s2) = b2
  do IO<Unit>:
    two : Socket <- peer_read(s2)
    peer_pair_act(kind, one, two)

def peer_pair_go(b1: Listener & Socket, kind: U32) -> IO(Unit):
  (l1, s1) = b1
  do IO<Unit>:
    one : Socket <- peer_read(s1)
    b2 : Listener & Socket <- peer_accept(l1)
    peer_pair_tail(one, b2, kind)

def peer_pair(l: Listener, kind: U32) -> IO(Unit):
  do IO<Unit>:
    b1 : Listener & Socket <- peer_accept(l)
    peer_pair_go(b1, kind)

# A peer for one connection: accept, read the request, close. A batch
# that dials answers 400 "eof" here, so the invalid-list claim fails by
# value and never hangs.
def peer_one_go(b: Listener & Socket) -> IO(Unit):
  (l, s) = b
  do IO<Unit>:
    one : Socket <- peer_read(s)
    x : Unit <- Socket.close(one)
    return Unit{}

def peer_one(l: Listener) -> IO(Unit):
  do IO<Unit>:
    b : Listener & Socket <- peer_accept(l)
    peer_one_go(b)

# The four scores: the alias server, the answering peer, the empty list,
# the silent peer.
def score_lib(r: Result<&1, &1, U32 & String, U32 & U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{counts}:
      eq2(counts, ONE_HELLO(), ONE_FIN())

def score_peer(r: Result<&1, &1, U32 & String, U32 & U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{counts}:
      eq2(counts, TWO_HELLO(), TWO_FINS())

def score_empty(r: Result<&1, &1, U32 & String, U32 & U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{counts}:
      eq2(counts, 0, 0)

def score_bad(r: Result<&1, &1, U32 & String, U32 & U32>) -> U32:
  match r:
    case Fail{(code, msg)}:
      b2u(Bool.and(U32.is_eq(code, 400), String.eq(msg, "bad request")))
    case Done{counts}:
      0

def score_eof(r: Result<&1, &1, U32 & String, U32 & U32>) -> U32:
  match r:
    case Fail{(code, msg)}:
      b2u(Bool.and(U32.is_eq(code, 400), String.eq(msg, "eof")))
    case Done{counts}:
      0

def batch_lib(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <-
      HTTPX.client.stream_concurrent_plain(~h_cli, HOST(), port, reqs_two())
    IO.pure(U32, score_lib(r))

def batch_empty(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <-
      HTTPX.client.stream_concurrent_plain(~h_cli, HOST(), port, reqs_empty())
    IO.pure(U32, score_empty(r))

def peer_client_score(kind: U32, r: Result<&1, &1, U32 & String, U32 & U32>) -> IO(U32):
  match kind:
    case 0:
      IO.pure(U32, score_peer(r))
    case _:
      IO.pure(U32, score_eof(r))

def peer_client_go(b: Listener & U32, +kind: U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, peer_pair(l, kind))
    r : Result<&1, &1, U32 & String, U32 & U32> <-
      HTTPX.client.stream_concurrent_plain(~h_cli, HOST(), port, reqs_peer())
    peer_client_score(kind, r)

def peer_client(port: U32, kind: U32) -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, (port + 1 : U32))
    peer_client_go(b, kind)

def bad_client_go(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, peer_one(l))
    r : Result<&1, &1, U32 & String, U32 & U32> <-
      HTTPX.client.stream_concurrent_plain(~h_cli, HOST(), port, reqs_mixed())
    IO.pure(U32, score_bad(r))

def bad_client(port: U32) -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, (port + 1 : U32))
    bad_client_go(b)

def clients(+port: U32) -> IO(U32):
  do IO<U32>:
    +s1 : U32 <- batch_lib(port)
    +s2 : U32 <- peer_client(port, 0)
    +s3 : U32 <- batch_empty(port)
    +s4 : U32 <- peer_client(port, 1)
    +s5 : U32 <- bad_client(port)
    IO.pure(U32, (s1 + s2 + s3 + s4 + s5 : U32))

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    x : Unit <- HTTPX.server.stream_concurrent_plain(~h_srv, l)
    return "up"

def main_go(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    +total : U32 <- clients(port)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    main_go(b)

#|5
