# io (lib_httpx_h1_fetch_bulk): the H1 content-length body lane with a
# body that spans several recvs. The server (server.on_h1_plain) answers
# a fixed 96 KB pattern (98304 bytes = 6 x 16384 recvs); the client
# (fetch_bytes_insecure over http://) must read it back whole.
#
# This is the lane that accumulated the body with List.append(rest, part)
# plus a full x_has_at_least re-walk per recv: quadratic, and
# linear-recursive past ~48 KB, which overflowed the interp machine stack
# (the hazard x_rev_push's header documents for the H2 lane). The body now
# rides reversed (x_rev_push/x_cat) with a missing-byte counter.
#
# The pattern is position-dependent (byte i is i mod 251), so the same
# bulk def builds the expected prefix on either side. Score: length x100
# + prefix x10 + checksum; golden 111.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX
import ../../lib/http.bend as HTTP

# Body size and the prefix length the client compares byte by byte.
def BULK_LEN() -> U32:
  98304

def BULK_PREFIX() -> U32:
  1024

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# The bulk pattern in order: byte i is (i mod 251). Tail-recursive build
# (n shrinks first, the checker reads arguments left to right) plus one
# x_cat at the end.
def bulk_go(+n: Nat, +i: Nat, +acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      bulk_go(p, Nat.add(i, 1n), U32.from_nat(Nat.mod(i, 251n)) <> acc)

def bulk(+n: Nat) -> List<&2, U32>:
  HTTP.x_cat(bulk_go(n, 0n, Nil{}))

# Sum of the same pattern without building it, for the checksum check.
def pattern_sum_go(+n: Nat, +i: Nat, +acc: U32) -> U32:
  match n:
    case 0n:
      acc
    case 1n+p:
      pattern_sum_go(p, Nat.add(i, 1n), U32.add(acc, U32.from_nat(Nat.mod(i, 251n))))

def pattern_sum(+n: Nat) -> U32:
  pattern_sum_go(n, 0n, 0)

def body_sum(+bs: List<&2, U32>, +acc: U32) -> U32:
  match bs:
    case Nil{}:
      acc
    case b <> t:
      body_sum(t, U32.add(acc, b))

def bulk_score(+body: List<&2, U32>) -> U32:
  +len_ok = b2u(U32.is_eq(HTTP.x_len32(body), BULK_LEN()))
  +pre_ok = HTTP.x_eq(HTTP.x_take32(BULK_PREFIX(), body), bulk(U32.to_nat(BULK_PREFIX())))
  +sum_ok = b2u(U32.is_eq(body_sum(body, 0), pattern_sum(U32.to_nat(BULK_LEN()))))
  U32.add(U32.add(U32.mul(len_ok, 100), U32.mul(pre_ok, 10)), sum_ok)

def bulk_check(r: Result<&1, &1, (U32 & String), List<&2, U32>>) -> IO(U32):
  match r:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{body}:
      IO.pure(U32, bulk_score(body))

# Server: one fixed 96 KB body per request, whatever was asked.
def bulk_service(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{method, path, headers, body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, bulk(U32.to_nat(BULK_LEN()))})

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

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    x : Unit <- HTTPX.server.on_h1_plain(~bulk_service, l)
    return "up"

def run(l: Listener, port: U32) -> IO(U32):
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    r : Result<&1, &1, (U32 & String), List<&2, U32>> <- HTTPX.fetch_bytes_insecure("http://127.0.0.1:" ++ U32.show(port) ++ "/bulk")
    +total : U32 <- bulk_check(r)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

def run_bound(b: Listener & U32) -> IO(U32):
  (l, port) = b
  run(l, port)

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 19588)
    run_bound(b)

#|111
