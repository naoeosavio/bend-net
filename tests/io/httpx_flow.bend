# lib (httpx_flow): big POST echo — 25 KB up through the flow sender
# (client slices to peer windows, server gives WU credit per DATA) and
# 25 KB down (server slices + client drain credits back). 25 KB covers 2
# DATA frames each way — max this lane can build in interp without a
# stack overflow (buf stops at ~26-27k one-byte nodes); bigger counts
# idênticos via binário C. Golden: 1 iff total==25000, fins==1, 200.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX

# 25 KB = 25000 one-byte nodes (46); Nat countdown local to this test
# (harness exception like listen_any: a U32 countdown without a list arg
# fails the termination checker; the lib path stays U32).
def httpx_flow.body.go(n: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+m:
      httpx_flow.body.go(m, 46 <> acc)

def httpx_flow.body() -> List<&2, U32>:
  httpx_flow.body.go(25000n, Nil{})

def httpx_echo(req: HTTPX.Request) -> IO(HTTPX.Response):
  match req:
    case HTTPX.Request{+method, +path, +headers, +body}:
      IO.pure(HTTPX.Response, HTTPX.Response{200, Nil{}, body})

def dbg_srv(n: U32) -> U32:
  n

def dbg_pair(counts: U32 & U32) -> U32:
  (total, fins) = counts
  (total + (fins * 1000 : U32) : U32)

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def client_score(counts: U32 & Bool) -> U32:
  (total, ok) = counts
  b2u(Bool.and(U32.is_eq(total, 25000), Bool.not(ok)))

def h(ev: HTTPX.StreamEv) -> HTTPX.StreamOut:
  match ev:
    case HTTPX.StreamHead{head}:
      HTTPX.StreamContinue{}
    case HTTPX.StreamData{chunk, fin}:
      HTTPX.StreamContinue{}

def counts2(counts: U32 & U32) -> U32 & Bool:
  (total, fins) = counts
  (total, Bool.not(U32.is_eq(fins, 1)))

def failscore(e: U32 & String) -> U32:
  (c, msg) = e
  ((c + 1000 : U32))

def client_score_counts(r: Result<&1, &1, U32 & String, U32 & U32>) -> U32:
  match r:
    case Fail{e}:
      failscore(e)
    case Done{counts}:
      client_score(counts2(counts))

def client(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <- HTTPX.client.stream_insecure(~h, "127.0.0.1", port, "POST", "/echo", Nil{}, httpx_flow.body())
    IO.pure(U32, client_score_counts(r))

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTPX.server.concurrent(~httpx_echo, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
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
    b : Listener & U32 <- listen_any(32n, 18440)
    main_go(b)

#|1
