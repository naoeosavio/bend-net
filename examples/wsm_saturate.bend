# Saturation + bench driver for lib/https.bend and lib/wsm.bend.
# Bend<->Bend loopback over ephemeral ports (no fixed-port clashes with
# the 19892/19893 echo peers). The HTTPS server is HTTPX.server.on and
# the WSS server is WSM.server_on (both IO.spawn per connection, so the
# N clients below overlap); each client is a single-shot insecure
# exchange (send_request_insecure / client_echo_insecure) against
# 127.0.0.1 with the test PEMs.
#
# Clients run N=20 per lane in parallel: run_* forks one client, then
# recurses for the rest while it flies, then joins — all N overlap.
# Prints SAT OK x/20 per lane plus BENCH lines (wall time comes from
# `time` around the run; Bend has no clock effect).
#
# Manual only — never runs in check.sh (needs loopback + TLS):
#   bend examples/wsm_saturate.bend
#   time bend examples/wsm_saturate.bend
import Base
import ../lib/tls.bend as TLS
import ../lib/wsm.bend as WSM
import ../lib/httpx.bend as HTTPX

def h2_echo(req: HTTPX.Request) -> IO(HTTPX.Response):
  match req:
    case HTTPX.Request{+method, +path, +headers, +body}:
      IO.pure(HTTPX.Response, HTTPX.Response{200, Nil{}, body})

def h.echo(ev: WSM.WSEv) -> IO(WSM.WSOut):
  match ev:
    case WSM.EvOpen{}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})
    case WSM.EvMsg{msg}:
      match msg:
        case WSM.WSText{text}:
          IO.pure(WSM.WSOut, WSM.OutMsg{WSM.WSText{text}})
        case WSM.WSBin{data}:
          IO.pure(WSM.WSOut, WSM.OutMsg{WSM.WSBin{data}})
    case WSM.EvPing{pay}:
      IO.pure(WSM.WSOut, WSM.wsm_out_pong(pay))
    case WSM.EvPong{pay}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})
    case WSM.EvClose{pay}:
      IO.pure(WSM.WSOut, WSM.wsm_out_close(pay))
    case WSM.EvError{code, msg}:
      IO.pure(WSM.WSOut, WSM.OutRaw{[]})

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def https_score(r: Result<&1, &1, U32 & String, String>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{body}:
      b2u(String.eq(body, "hello"))

def wss_score(r: Result<&1, &1, U32 & String, String>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{body}:
      b2u(String.eq(body, "Hi"))

law https_server:
  for l: Listener
  IO(String)

def https_server(l):
  do IO<String>:
    x : Unit <- HTTPX.server.on(~h2_echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    return "up"

law wss_server:
  for l: Listener
  IO(String)

def wss_server(l):
  do IO<String>:
    x : Unit <- WSM.server_on(~h.echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    return "up"

law client_https:
  for port: U32
  IO(U32)

def client_https(port):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, String> <- HTTPX.request_insecure("127.0.0.1", port, "/echo", "POST", Nil{}, "hello")
    IO.pure(U32, https_score(r))

law client_wss:
  for port: U32
  IO(U32)

def client_wss(port):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, String> <- WSM.client_echo_insecure("127.0.0.1", port, "/chat", "dGhlIHNhbXBsZSBub25jZQ==", "Hi")
    IO.pure(U32, wss_score(r))

law run_https:
  for port: U32
  for n: Nat
  IO(U32)

def run_https(port, n):
  match n:
    case 0n:
      IO.pure(U32, 0)
    case 1n+t:
      +p = port
      do IO<U32>:
        chan : Chan(U32) <- IO.fork(U32, client_https(p))
        rest : U32 <- run_https(p, t)
        a : U32 <- IO.join(U32, chan)
        IO.pure(U32, (a + rest : U32))

law run_wss:
  for port: U32
  for n: Nat
  IO(U32)

def run_wss(port, n):
  match n:
    case 0n:
      IO.pure(U32, 0)
    case 1n+t:
      +p = port
      do IO<U32>:
        chan : Chan(U32) <- IO.fork(U32, client_wss(p))
        rest : U32 <- run_wss(p, t)
        a : U32 <- IO.join(U32, chan)
        IO.pure(U32, (a + rest : U32))

law listen_retry:
  for port: U32
  for r: Result<&1, &1, U32 & String, Listener>
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
        r : Result<&1, &1, U32 & String, Listener> <- TCP.listen(port)
        listen_retry(port, r, rest)

law main_wss:
  for b: Listener & U32
  for h_ok: U32
  IO(U32)

def main_wss(b, h_ok):
  (l2, port2) = b
  +h = h_ok
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, wss_server(l2))
    w_ok : U32 <- run_wss(port2, 20n)
    +w : U32 = w_ok
    s1 : Unit <- IO.print("SAT HTTPS OK " ++ U32.show(h) ++ "/20")
    s2 : Unit <- IO.print("SAT WSS OK " ++ U32.show(w) ++ "/20")
    q1 : Unit <- IO.print("BENCH https_clients 20")
    q2 : Unit <- IO.print("BENCH wss_clients 20")
    q3 : Unit <- IO.print("BENCH https_ok " ++ U32.show(h))
    q4 : Unit <- IO.print("BENCH wss_ok " ++ U32.show(w))
    z : Unit <- IO.die(Unit, 0, "")
    return (h + w : U32)

law main_https:
  for b: Listener & U32
  IO(U32)

def main_https(b):
  (l, port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, https_server(l))
    h_ok : U32 <- run_https(port, 20n)
    b2 : Listener & U32 <- listen_any(32n, 18650)
    main_wss(b2, h_ok)

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 18550)
    main_https(b)
