# io (http1_server_stream): the TASK-081 server loop of lib/http1.bend,
# driven directly (no facade in the path). Seven cases, one connection
# each, all over plaintext TCP templates:
#   1. fold_chunk ......... a valid chunked POST on the buffered fold:
#                          the loop decodes, answers 200 with the body
#                          echoed, then re-seeds the keep-alive.
#   2. fold_chunk_413 ..... a chunked body over the 16384 cap: the fold
#                          answers 413 and closes.
#   3. fold_bad_single .... a malformed chunked body: exactly ONE 400,
#                          then EOF. The machine this loop replaces
#                          answered 400 twice (the respond ran, then the
#                          rejoin path rendered a second status line);
#                          a second status line in the raw fails the case.
#   4. stream_chunk ....... the stream form: a chunked POST whose first
#                          data event answers RespondEarly echo 200.
#   5. stream_cancel ...... the stream form: the data event answers
#                          Cancel; the connection closes with no bytes.
#   6. stream_500 ......... the stream form: RespondEarly with a CR/LF
#                          inside a handler header. The answer rides the
#                          same render gate the buffered lane owns, so
#                          the peer sees a bare 500, never the split.
#   7. head_431 ........... a request head past the 16384-byte cap: the
#                          module answers 431 (the cap was pinned only by
#                          the facade copy before this file).
# Golden 7.
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

# The buffered handler: echoes the folded body.
def echo(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, body})

# The stream handler of case 4: the head continues, the first data
# chunk answers the echo.
def sh_echo(ev: HTTP.SrvEv) -> HTTP.SrvOut:
  match ev:
    case HTTP.SrvReqHead{slot, head}:
      HTTP.Continue{}
    case HTTP.SrvReqData{slot, +chunk, fin}:
      HTTP.RespondEarly{HTTP.Response{200, Nil{}, chunk}}

# The stream handler of case 5: the data event cancels, so the server
# closes without a response.
def sh_cancel(ev: HTTP.SrvEv) -> HTTP.SrvOut:
  match ev:
    case HTTP.SrvReqHead{slot, head}:
      HTTP.Continue{}
    case HTTP.SrvReqData{slot, +chunk, fin}:
      HTTP.Cancel{}

# The stream handler of case 6: the answer carries a CR/LF inside a
# header value, the classic response-splitting shape.
def sh_bad(ev: HTTP.SrvEv) -> HTTP.SrvOut:
  match ev:
    case HTTP.SrvReqHead{slot, head}:
      HTTP.Continue{}
    case HTTP.SrvReqData{slot, +chunk, fin}:
      HTTP.RespondEarly{HTTP.Response{200, HTTP.Hdr{"x-echo", "v\r\nx-split: 1"} <> Nil{}, Nil{}}}

# Request texts.
def req_chunked() -> String:
  "POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\n\r\n"

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
  "POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4E20\r\n"
    ++ filler(20000) ++ "\r\n0\r\n\r\n"

def req_bad() -> String:
  "POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nzz\r\nAB"

def req_cl() -> String:
  "POST /up HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\nhi"

def req_big_head() -> String:
  "GET /a HTTP/1.1\r\nHost: a\r\nx-pad: " ++ filler(17000) ++ "\r\n\r\n"

# Scoring helpers: each matches its own parameter, one marker set each.
def hit(r: Result<&1, &1, U32 & String, String>, +want: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+raw}:
      b2u(String.contains(raw, want))

def hit2(r: Result<&1, &1, U32 & String, String>, +want: String, +want2: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+raw}:
      U32.mul(b2u(String.contains(raw, want)), b2u(String.contains(raw, want2)))

def hit_not(r: Result<&1, &1, U32 & String, String>, +want: String, +never: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+raw}:
      U32.mul(b2u(String.contains(raw, want)), b2u(Bool.not(String.contains(raw, never))))

def hit_eof(r: Result<&1, &1, U32 & String, String>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+raw}:
      b2u(String.is_empty(raw))

def hit_one_400(r: Result<&1, &1, U32 & String, String>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+raw}:
      U32.mul(b2u(String.contains(raw, "HTTP/1.1 400")), b2u(Bool.not(String.contains(raw, "\r\n\r\nHTTP/1.1"))))

# Read-and-close ladders, one scorer each.
def got_hit(got: Socket & Result<&1, &1, U32 & String, String>, +want: String) -> IO(U32):
  (s, r) = got
  do IO<U32>:
    x : Unit <- Socket.close(s)
    IO.pure(U32, hit(r, want))

def got_hit2(got: Socket & Result<&1, &1, U32 & String, String>, +want: String, +want2: String) -> IO(U32):
  (s, r) = got
  do IO<U32>:
    x : Unit <- Socket.close(s)
    IO.pure(U32, hit2(r, want, want2))

def got_hit_not(got: Socket & Result<&1, &1, U32 & String, String>, +want: String, +never: String) -> IO(U32):
  (s, r) = got
  do IO<U32>:
    x : Unit <- Socket.close(s)
    IO.pure(U32, hit_not(r, want, never))

def got_eof(got: Socket & Result<&1, &1, U32 & String, String>) -> IO(U32):
  (s, r) = got
  do IO<U32>:
    x : Unit <- Socket.close(s)
    IO.pure(U32, hit_eof(r))

# The single-400 case: score the first read, then the second read must
# see EOF and nothing else.
def bad_eof(got2: Socket & Result<&1, &1, U32 & String, String>, +one: U32) -> IO(U32):
  (s2, r2) = got2
  do IO<U32>:
    x : Unit <- Socket.close(s2)
    IO.pure(U32, U32.and(one, hit_eof(r2)))

def bad_read2(got1: Socket & Result<&1, &1, U32 & String, String>) -> IO(U32):
  (s1, r1) = got1
  do IO<U32>:
    got2 : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s1, 16384)
    bad_eof(got2, hit_one_400(r1))

# Send ladders: the socket rides the send result, one scorer each.
def sent_hit(sent: Socket & Result<&1, &1, U32 & String, Unit>, +want: String) -> IO(U32):
  (s, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 16384)
        got_hit(got, want)

def sent_hit2(sent: Socket & Result<&1, &1, U32 & String, Unit>, +want: String, +want2: String) -> IO(U32):
  (s, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 16384)
        got_hit2(got, want, want2)

def sent_hit_not(sent: Socket & Result<&1, &1, U32 & String, Unit>, +want: String, +never: String) -> IO(U32):
  (s, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 16384)
        got_hit_not(got, want, never)

def sent_eof(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  (s, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 16384)
        got_eof(got)

def sent_bad(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  (s, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got1 : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 16384)
        bad_read2(got1)

# Connect and send: one ladder per scorer shape.
def conn_hit(conn: Result<&1, &1, U32 & String, Socket>, +req: String, +want: String) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req)
        sent_hit(sent, want)

def conn_hit2(conn: Result<&1, &1, U32 & String, Socket>, +req: String, +want: String, +want2: String) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req)
        sent_hit2(sent, want, want2)

def conn_hit_not(conn: Result<&1, &1, U32 & String, Socket>, +req: String, +want: String, +never: String) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req)
        sent_hit_not(sent, want, never)

def conn_eof(conn: Result<&1, &1, U32 & String, Socket>, +req: String) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req)
        sent_eof(sent)

def conn_bad(conn: Result<&1, &1, U32 & String, Socket>, +req: String) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req)
        sent_bad(sent)

# Server sides: the module entries accept themselves.
def fold_side(l: Listener) -> IO(Unit):
  HTTP1.server.once(~echo, l)

def stream_echo_side(l: Listener) -> IO(Unit):
  HTTP1.server.stream.once(~sh_echo, l)

def stream_cancel_side(l: Listener) -> IO(Unit):
  HTTP1.server.stream.once(~sh_cancel, l)

def stream_bad_side(l: Listener) -> IO(Unit):
  HTTP1.server.stream.once(~sh_bad, l)

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

# One case: fork the side, dial, drive the ladder. The listen pair is
# passed whole and destructured at the top of the runner (a destructuring
# cannot follow a do bind).
def run_hit(~side: Listener -> IO(Unit), b: Listener & U32, +req: String, +want: String) -> IO(U32):
  (l, p) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", p)
    conn_hit(conn, req, want)

def run_hit2(~side: Listener -> IO(Unit), b: Listener & U32, +req: String, +want: String, +want2: String) -> IO(U32):
  (l, p) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", p)
    conn_hit2(conn, req, want, want2)

def run_hit_not(~side: Listener -> IO(Unit), b: Listener & U32, +req: String, +want: String, +never: String) -> IO(U32):
  (l, p) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", p)
    conn_hit_not(conn, req, want, never)

def run_eof(~side: Listener -> IO(Unit), b: Listener & U32, +req: String) -> IO(U32):
  (l, p) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", p)
    conn_eof(conn, req)

def run_bad(b: Listener & U32, +req: String) -> IO(U32):
  (l, p) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, fold_side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", p)
    conn_bad(conn, req)

def case_hit(~side: Listener -> IO(Unit), +port: U32, +req: String, +want: String) -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(8n, port)
    run_hit(~side, b, req, want)

def case_hit2(~side: Listener -> IO(Unit), +port: U32, +req: String, +want: String, +want2: String) -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(8n, port)
    run_hit2(~side, b, req, want, want2)

def case_hit_not(~side: Listener -> IO(Unit), +port: U32, +req: String, +want: String, +never: String) -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(8n, port)
    run_hit_not(~side, b, req, want, never)

def case_eof(~side: Listener -> IO(Unit), +port: U32, +req: String) -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(8n, port)
    run_eof(~side, b, req)

def case_bad(+port: U32, +req: String) -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(8n, port)
    run_bad(b, req)

def main() -> IO(U32):
  do IO<U32>:
    a : U32 <- case_hit2(~fold_side, 20610, req_chunked(), "HTTP/1.1 200", "Wikipedia")
    b : U32 <- case_hit(~fold_side, 20611, req_over(), "HTTP/1.1 413")
    c : U32 <- case_bad(20612, req_bad())
    d : U32 <- case_hit2(~stream_echo_side, 20613, req_chunked(), "HTTP/1.1 200", "Wiki")
    e : U32 <- case_eof(~stream_cancel_side, 20614, req_cl())
    f : U32 <- case_hit_not(~stream_bad_side, 20615, req_cl(), "HTTP/1.1 500", "x-split: 1")
    g : U32 <- case_hit(~stream_echo_side, 20616, req_big_head(), "HTTP/1.1 431")
    +total : U32 = (a + b + c + d + e + f + g : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|7
