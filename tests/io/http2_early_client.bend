# io (httpx_h2_early_client): a Bend streaming client whose body outruns
# the connection window must still read an early answer (task-042 phase
# 2b, the client-side discovery of phase 2).
#
# The server is HTTPX.server.stream answering RespondEarly on the head
# (200 plus a short body) and Continue on data; the client is
# HTTPX.client.stream_insecure POSTing 70000 bytes, so the flow sender
# runs out of the default 65535-byte window while the response is
# already on the wire. Before the fix the sender dropped the response
# HEADERS it read while waiting for credit, kept sending, and then turned
# the server's RST_STREAM into Fail 502; now it stops the send, hands the
# frame's wire bytes back as the read seed, and the drain delivers the
# 200 and the body.
#
# The handler cancels the drain on any status but 200, so the score
# covers both halves: 1 iff the drain counted exactly the early body with
# one END_STREAM, golden 1.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18562

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
# reverse (the pattern tests/io/wsm_bulk_frame.bend uses).
def body_go(+n: Nat, +acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      body_go(p, 46 <> acc)

def body(+n: Nat) -> List<&2, U32>:
  HTTP.x_cat(body_go(n, Nil{}))

# Server: answer the head early, never read the body.
def h(ev: HTTP.SrvEv) -> HTTP.SrvOut:
  match ev:
    case HTTP.SrvReqHead{slot, head}:
      HTTP.RespondEarly{HTTP.Response{200, Nil{}, EARLY_BODY()}}
    case HTTP.SrvReqData{slot, chunk, fin}:
      HTTP.Continue{}

def status_ok(+h: HTTP.Head) -> Bool:
  match h:
    case HTTP.Head{status, headers}:
      U32.is_eq(status, 200)

def hcl_head(ok: Bool) -> HTTP.StreamOut:
  match ok:
    case True{}:
      HTTP.StreamContinue{}
    case False{}:
      HTTP.StreamCancel{}

# Client handler: a non-200 head cancels the drain, so the counts that
# follow cannot score.
def hcl(ev: HTTP.StreamEv) -> HTTP.StreamOut:
  match ev:
    case HTTP.StreamHead{head}:
      hcl_head(status_ok(head))
    case HTTP.StreamData{chunk, fin}:
      HTTP.StreamContinue{}

# Drain counts: total bytes and END_STREAMs seen.
def counts_ok(counts: U32 & U32) -> U32:
  (total, fins) = counts
  U32.mul(b2u(U32.is_eq(total, HTTP.x_len32(EARLY_BODY()))), b2u(U32.is_eq(fins, 1)))

def client_score(r: Result<&1, &1, U32 & String, U32 & U32>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{counts}:
      counts_ok(counts)

def client(+port: U32) -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, U32 & String, U32 & U32> <- HTTPX.client.stream_insecure(~hcl, "127.0.0.1", port, "POST", "/early", Nil{}, body(BODY_LEN()))
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
