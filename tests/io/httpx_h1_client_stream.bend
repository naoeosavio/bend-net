# lib (lib_httpx_h1_client_stream): streaming download over plaintext H1.
# Server is the one-shot HTTPX.server.on_h1_plain echo; client is
# HTTPX.client.stream_plain POST "hello" with a pure Continue handler
# (no body accumulation, O(1) per chunk). Golden 10 iff total bytes 5,
# plus 1 iff a cancel-on-head handler reports Fail 8 (close, no RST on
# this lane) — 11 total.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

law h_all:
  for ev: HTTPX.StreamEv
  HTTPX.StreamOut

def h_all(ev):
  match ev:
    case HTTPX.StreamHead{head}:
      HTTPX.StreamContinue{}
    case HTTPX.StreamData{chunk, fin}:
      HTTPX.StreamContinue{}

law h_cancel:
  for ev: HTTPX.StreamEv
  HTTPX.StreamOut

def h_cancel(ev):
  match ev:
    case HTTPX.StreamHead{head}:
      HTTPX.StreamCancel{}
    case HTTPX.StreamData{chunk, fin}:
      HTTPX.StreamCancel{}

law score_stream:
  for r: Result<&1, &1, (U32 & String), (U32 & U32)>
  U32

def score_stream(r):
  match r:
    case Fail{e}:
      0
    case Done{counts}:
      (total, chunks) = counts
      b2u(U32.is_eq(total, 5))

law score_cancel:
  for r: Result<&1, &1, (U32 & String), (U32 & U32)>
  U32

def score_cancel(r):
  match r:
    case Fail{e}:
      (code, msg) = e
      b2u(U32.is_eq(code, 8))
    case Done{counts}:
      0

law echo_service:
  for req: HTTPX.Request
  IO(HTTPX.Response)

def echo_service(req):
  match req:
    case HTTPX.Request{method, path, headers, body}:
      IO.pure(HTTPX.Response, HTTPX.Response{200, Nil{}, body})

law client:
  for +port: U32
  IO(U32)

def client(port):
  do IO<U32>:
    r1 : Result<&1, &1, (U32 & String), (U32 & U32)> <- HTTPX.client.stream_plain(~h_all, "127.0.0.1", port, "POST", "/echo", Nil{}, HTTPX.x_str_bytes("hello"))
    r2 : Result<&1, &1, (U32 & String), (U32 & U32)> <- HTTPX.client.stream_plain(~h_cancel, "127.0.0.1", port, "POST", "/echo", Nil{}, HTTPX.x_str_bytes("hello"))
    +total : U32 = (score_stream(r1) * 10 + score_cancel(r2) : U32)
    IO.pure(U32, total)

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTPX.server.on_h1_plain(~echo_service, l)
    return "up"

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

law main_go:
  for b: Listener & U32
  IO(U32)

def main_go(b):
  (l, port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    +a : U32 <- client(port)
    +total : U32 = (a : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 19741)
    main_go(b)

#|11
