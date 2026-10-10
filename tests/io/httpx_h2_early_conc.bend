# io (httpx_h2_early_conc): a concurrent client whose body outruns the
# connection window must still read an early answer (task-042 follow-up
# of phase 2b, the lane phase 2b left with an explicit discard).
#
# The server is HTTPX.server.stream answering RespondEarly on the head
# (200 plus a short body) and Continue on data; the client is
# HTTPX.client.concurrent_insecure POSTing 70000 bytes on one stream, so
# the flow sender runs out of the default 65535-byte window while the
# response is already on the wire. client_conc.send_kept dropped the
# frames the sender had read: the early HEADERS never reached
# client_conc.drain, which then saw stray DATA (Fail 502) or nothing at
# all (hang) for a response that had already arrived. Now the seeds
# accumulate in wire order and seed the drain, which delivers the 200 and
# the body.
#
# The scoring function counts a response 1 iff status 200 and the early
# body, so a Fail or a hang scores 0, golden 1.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX

def PORT() -> U32:
  18567

# Bigger than the RFC 9113 section 6.9.2 default window, so the sender
# must stop and read credit before the body is out.
def BODY_LEN() -> Nat:
  70000n

def EARLY_BODY() -> List<&2, U32>:
  [101, 97, 114, 108, 121]

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# Body bytes: position-independent filler, tail-recursive plus one x_cat
# reverse (the pattern tests/io/httpx_h2_early_client.bend uses).
def body_go(+n: Nat, +acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      body_go(p, 46 <> acc)

def body(+n: Nat) -> List<&2, U32>:
  HTTPX.x_cat(body_go(n, Nil{}))

# Server: answer the head early, never read the body.
def h(ev: HTTPX.SrvEv) -> HTTPX.SrvOut:
  match ev:
    case HTTPX.SrvReqHead{slot, head}:
      HTTPX.RespondEarly{HTTPX.Response{200, Nil{}, EARLY_BODY()}}
    case HTTPX.SrvReqData{slot, chunk, fin}:
      HTTPX.Continue{}

# Concurrent scorer: one point for the early response, nothing else.
def hcl(resp: HTTPX.Response) -> U32:
  match resp:
    case HTTPX.Response{+status, +headers, +body}:
      U32.mul(b2u(U32.is_eq(status, 200)), HTTPX.x_eq(body, EARLY_BODY()))

def reqs() -> List<&2, HTTPX.Request>:
  [HTTPX.Request{"POST", "/early", Nil{}, body(BODY_LEN())}]

def client_score(r: Result<&1, &1, U32 & String, U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+total}:
      total

def client(port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32> <- HTTPX.client.concurrent_insecure(~hcl, "127.0.0.1", port, reqs())
    IO.pure(U32, client_score(r))

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    x : Unit <- HTTPX.server.stream(~h, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    return "up"

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

def run(l: Listener, +port: U32) -> IO(U32):
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    +score : U32 <- client(port)
    w : Unit <- IO.print(U32.show(score))
    z : Unit <- IO.die(Unit, 0, "")
    return score

def run_bound(b: Listener & U32) -> IO(U32):
  (l, port) = b
  run(l, port)

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    run_bound(b)

#|1
