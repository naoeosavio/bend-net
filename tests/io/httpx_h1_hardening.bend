# io (httpx_h1_hardening): the H1 server must refuse a request head it
# cannot frame, and tell the peer why (task-042 phase 6, RFC 9112 sections
# 3.2 and 6.3).
#
# Ten plaintext connections, one case each, against server.on_h1_plain:
#   case 0: HTTP/1.1 without Host            -> 400 (host required)
#   case 1: HTTP/1.0 without Host            -> 200 (1.0 may omit it)
#   case 2: two Host fields                  -> 400 (duplicate host)
#   case 3: an empty Host                    -> 400 (bad host)
#   case 4: Content-Length + Transfer-Encoding -> 400 (the smuggling pair)
#   case 5: two Content-Length fields        -> 400 (duplicate)
#   case 6: Content-Length: -1               -> 400 (not a decimal)
#   case 7: Transfer-Encoding: gzip          -> 400 (unframable coding)
#   case 8: a head past the 16384-byte cap   -> 431 (was a silent close)
#   case 9: a clean POST                     -> 200 + the echoed body
#   case 10: the 101-upgrade lane, the smuggling pair -> 400
#   case 11: the streaming lane, no Host     -> 400
#
# The last two are the guards on the other side: a 1.0 peer without Host is
# still served, and a valid request still reaches the handler. Before the
# fix every refusal above was a silent close (or, for the framing pair, a
# served request whose body the two framings disagreed on).
#
# Score: one point per case, golden 12.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX

def PORT() -> U32:
  49340

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def echo(req: HTTPX.Request) -> IO(HTTPX.Response):
  match req:
    case HTTPX.Request{method, path, headers, body}:
      IO.pure(HTTPX.Response, HTTPX.Response{200, Nil{}, body})

# The head filler of the oversized case: one long header field, no blank
# line until the end. @unsafe for the same reason the chunk test's filler
# is: the checker reads `65 <> acc` as a non-decreasing argument.
@unsafe
def filler.go(+n: U32, +acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0:
      acc
    case _:
      filler.go((n - 1 : U32), 65 <> acc)

def filler(n: U32) -> String:
  HTTPX.x_bytes_str(filler.go(n, Nil{}))

def req_no_host() -> String:
  "GET /a HTTP/1.1\r\n\r\n"

def req_10() -> String:
  "GET /a HTTP/1.0\r\n\r\n"

def req_dup_host() -> String:
  "GET /a HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"

def req_empty_host() -> String:
  "GET /a HTTP/1.1\r\nHost:\r\n\r\n"

def req_te_cl() -> String:
  "POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"

def req_dup_cl() -> String:
  "POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc"

def req_bad_cl() -> String:
  "POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n"

def req_te_gzip() -> String:
  "POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n"

def req_big_head() -> String:
  "GET /a HTTP/1.1\r\nHost: a\r\nx-pad: " ++ filler(17000) ++ "\r\n\r\n"

def req_ok() -> String:
  "POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc"

def hit(r: Result<&1, &1, U32 & String, String>, +want: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      b2u(String.starts_with(resp, "HTTP/1.1 " ++ want))

def hit_body(r: Result<&1, &1, U32 & String, String>, +want: String, +body: String) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+resp}:
      U32.mul(hit(Done{resp}, want), b2u(String.contains(resp, body)))

def scored(m: Socket & Result<&1, &1, U32 & String, String>, +want: String) -> IO(U32):
  (s, r) = m
  do IO<U32>:
    x : Unit <- Socket.close(s)
    IO.pure(U32, hit(r, want))

def scored_body(m: Socket & Result<&1, &1, U32 & String, String>, +want: String, +body: String) -> IO(U32):
  (s, r) = m
  do IO<U32>:
    x : Unit <- Socket.close(s)
    IO.pure(U32, hit_body(r, want, body))

def case_sent(sent: Socket & Result<&1, &1, U32 & String, Unit>, +want: String, +body: String) -> IO(U32):
  (s, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- Socket.close(s)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        got : Socket & Result<&1, &1, U32 & String, String> <- TCP.recv(s, 32768)
        scored_body(got, want, body)

def raw_case(conn: Result<&1, &1, U32 & String, Socket>, +req: String, +want: String, +body: String) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        sent : Socket & Result<&1, &1, U32 & String, Unit> <- TCP.send(sock, req)
        case_sent(sent, want, body)

def k_close(sock: Socket, rest: List<&2, U32>) -> IO(Unit):
  Socket.close(sock)

def sh(ev: HTTPX.SrvEv) -> HTTPX.SrvOut:
  match ev:
    case HTTPX.SrvReqHead{slot, head}:
      HTTPX.Continue{}
    case HTTPX.SrvReqData{slot, chunk, fin}:
      HTTPX.Continue{}

def server_side(l: Listener) -> IO(Unit):
  HTTPX.server.on_h1_plain(~echo, l)

def open_side(l: Listener) -> IO(Unit):
  HTTPX.server.on_h1_open_plain(~echo, ~k_close, l)

def stream_side(l: Listener) -> IO(Unit):
  HTTPX.server.stream_plain(~sh, l)

def case_open(b: Listener & U32, +req: String, +want: String) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, open_side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", port)
    raw_case(conn, req, want, "")

def case_stream(b: Listener & U32, +req: String, +want: String) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, stream_side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", port)
    raw_case(conn, req, want, "")

def case_of(b: Listener & U32, +req: String, +want: String, +body: String) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(Unit) <- IO.fork(Unit, server_side(l))
    conn : Result<&1, &1, U32 & String, Socket> <- TCP.connect("127.0.0.1", port)
    raw_case(conn, req, want, body)

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

def run_one(+port: U32, +req: String, +want: String, +body: String) -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(8n, port)
    case_of(b, req, want, body)

def run_open(+port: U32, +req: String, +want: String) -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(8n, port)
    case_open(b, req, want)

def run_stream(+port: U32, +req: String, +want: String) -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(8n, port)
    case_stream(b, req, want)

def main() -> IO(U32):
  do IO<U32>:
    a : U32 <- run_one(PORT(), req_no_host(), "400", "")
    b : U32 <- run_one((PORT() + 1 : U32), req_10(), "200", "")
    c : U32 <- run_one((PORT() + 2 : U32), req_dup_host(), "400", "")
    d : U32 <- run_one((PORT() + 3 : U32), req_empty_host(), "400", "")
    e : U32 <- run_one((PORT() + 4 : U32), req_te_cl(), "400", "")
    f : U32 <- run_one((PORT() + 5 : U32), req_dup_cl(), "400", "")
    g : U32 <- run_one((PORT() + 6 : U32), req_bad_cl(), "400", "")
    h : U32 <- run_one((PORT() + 7 : U32), req_te_gzip(), "400", "")
    i : U32 <- run_one((PORT() + 8 : U32), req_big_head(), "431", "")
    j : U32 <- run_one((PORT() + 9 : U32), req_ok(), "200", "abc")
    k : U32 <- run_open((PORT() + 10 : U32), req_te_cl(), "400")
    m : U32 <- run_stream((PORT() + 11 : U32), req_no_host(), "400")
    +total : U32 = (a + b + c + d + e + f + g + h + i + j + k + m : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|12
