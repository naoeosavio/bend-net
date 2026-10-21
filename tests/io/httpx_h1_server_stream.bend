# lib (lib_httpx_h1_server_stream): streaming upload over plaintext H1.
# Server is HTTPX.server.stream_plain with a pure per-chunk-cap handler
# (cap 3): Head -> Continue; Data "cancel" -> Cancel (close, no response);
# Data chunk>3 -> RespondEarly 413; Data <=3 -> RespondEarly echo 200.
# Client is three one-shot HTTPX.request.plain POSTs ("hi" echo 200,
# "hello" early 413, "cancel" closed without response). Golden 111.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX
import ../../lib/http.bend as HTTP

law b2u:
  for b: Bool
  U32

def b2u(b):
  match b:
    case True{}:
      1
    case False{}:
      0

law cap:
  U32

def cap():
  3

law over_cap:
  for chunk: List<&2, U32>
  Bool

def over_cap(chunk):
  U32.is_gt(HTTP.x_len32(chunk), cap())

law is_cancel:
  for chunk: List<&2, U32>
  Bool

def is_cancel(chunk):
  U32.is_eq(HTTP.x_eq(chunk, HTTP.x_str_bytes("cancel")), 1)

law h_data_over:
  for over: Bool
  for chunk: List<&2, U32>
  HTTP.SrvOut

def h_data_over(over, chunk):
  match over:
    case True{}:
      HTTP.RespondEarly{HTTP.Response{413, Nil{}, Nil{}}}
    case False{}:
      HTTP.RespondEarly{HTTP.Response{200, Nil{}, chunk}}

law h_data:
  for cancel: Bool
  for over: Bool
  for chunk: List<&2, U32>
  HTTP.SrvOut

def h_data(cancel, over, chunk):
  match cancel:
    case True{}:
      HTTP.Cancel{}
    case False{}:
      h_data_over(over, chunk)

law h:
  for ev: HTTP.SrvEv
  HTTP.SrvOut

def h(ev):
  match ev:
    case HTTP.SrvReqHead{slot, head}:
      HTTP.Continue{}
    case HTTP.SrvReqData{slot, +chunk, fin}:
      h_data(is_cancel(chunk), over_cap(chunk), chunk)

law score_echo:
  for r: Result<&1, &1, (U32 & String), HTTP.Response>
  U32

def score_echo(r):
  match r:
    case Fail{e}:
      0
    case Done{resp}:
      match resp:
        case HTTP.Response{status, headers, body}:
          b2u(Bool.and(U32.is_eq(status, 200), U32.is_eq(HTTP.x_eq(body, HTTP.x_str_bytes("hi")), 1)))

law score_early:
  for r: Result<&1, &1, (U32 & String), HTTP.Response>
  U32

def score_early(r):
  match r:
    case Fail{e}:
      0
    case Done{resp}:
      match resp:
        case HTTP.Response{status, headers, body}:
          b2u(U32.is_eq(status, 413))

law score_cancel:
  for r: Result<&1, &1, (U32 & String), HTTP.Response>
  U32

def score_cancel(r):
  match r:
    case Fail{e}:
      1
    case Done{resp}:
      0

law client:
  for +port: U32
  IO(U32)

def client(port):
  do IO<U32>:
    r1 : Result<&1, &1, (U32 & String), HTTP.Response> <- HTTPX.request.plain("127.0.0.1", port, "POST", "/up", Nil{}, HTTP.x_str_bytes("hi"))
    r2 : Result<&1, &1, (U32 & String), HTTP.Response> <- HTTPX.request.plain("127.0.0.1", port, "POST", "/up", Nil{}, HTTP.x_str_bytes("hello"))
    r3 : Result<&1, &1, (U32 & String), HTTP.Response> <- HTTPX.request.plain("127.0.0.1", port, "POST", "/up", Nil{}, HTTP.x_str_bytes("cancel"))
    +total : U32 = (score_echo(r1) * 100 + score_early(r2) * 10 + score_cancel(r3) : U32)
    IO.pure(U32, total)

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTPX.server.stream_plain(~h, l)
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
    b : Listener & U32 <- listen_any(32n, 19731)
    main_go(b)

#|111
