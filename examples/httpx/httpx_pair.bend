# Two 64 KiB POSTs on one connection: the client half of the connection
# window (task-063 phase 7e). Manual only, never in the gate.
#
# The peer is node:http2, which enforces its own receive window and ends
# the session with FLOW_CONTROL_ERROR when a DATA byte passes it. The two
# bodies are one byte past the initial 65535-byte connection window, so
# the second send must start from the window the first one left, not from
# the constant seed.
#   node examples/httpx/mux_node_echoserv.js 19893 2 &
#   bend examples/httpx/httpx_pair.bend
import Base
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  19893

def HOST() -> String:
  "127.0.0.1"

def BODY() -> U32:
  65536

@unsafe
def fill_go(n: Nat, +b: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      fill_go(p, b, b <> acc)

def fill(n: U32, +b: U32) -> List<&2, U32>:
  fill_go(U32.to_nat(n), b, Nil{})

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def bytes_go(+pay: List<&2, U32>, +b: U32, ok: Bool) -> Bool:
  match pay:
    case Nil{}:
      ok
    case +h <> t:
      bytes_go(t, b, Bool.and(ok, U32.is_eq(h, b)))

# One point for a 200 whose body echoes the right bytes.
def h(resp: HTTP.Response) -> U32:
  match resp:
    case HTTP.Response{+status, +headers, +body}:
      U32.mul(b2u(U32.is_eq(status, 200)), U32.mul(b2u(U32.is_eq(HTTP.x_len32(body), BODY())), b2u(Bool.or(bytes_go(body, 65, True{}), bytes_go(body, 66, True{})))))

def reqs() -> List<&2, HTTP.Request>:
  [HTTP.Request{"POST", "/echo", Nil{}, fill(BODY(), 65)},
   HTTP.Request{"POST", "/echo", Nil{}, fill(BODY(), 66)}]

def report(r: Result<&1, &1, U32 & String, U32>) -> IO(Unit):
  match r:
    case Fail{(code, msg)}:
      do IO<Unit>:
        x : Unit <- IO.print("FAIL " ++ U32.show(code) ++ " " ++ msg)
        IO.die(Unit, 1, "")
    case Done{+score}:
      do IO<Unit>:
        x : Unit <- IO.print("DONE pair " ++ U32.show(score))
        IO.die(Unit, 0, "")

# `seq` sends the two requests in order on one connection, so the second
# send seeds from the window the first exchange left in the `CliSt`
# (TASK-063 phase 7c). The default sends them in flight (phase 7e).
# The ordered lane answers the response list; one point for each good
# echo, the same score the concurrent handler sums.
def body_ok(resp: HTTP.Response) -> U32:
  match resp:
    case HTTP.Response{+status, +headers, +body}:
      U32.mul(b2u(U32.is_eq(status, 200)), U32.mul(b2u(U32.is_eq(HTTP.x_len32(body), BODY())), b2u(Bool.or(bytes_go(body, 65, True{}), bytes_go(body, 66, True{})))))

def oks(+rs: List<&2, HTTP.Response>, acc: U32) -> U32:
  match rs:
    case Nil{}:
      acc
    case +h <> t:
      oks(t, U32.add(acc, body_ok(h)))

def score_list(r: Result<&1, &1, U32 & String, List<&2, HTTP.Response>>) -> Result<&1, &1, U32 & String, U32>:
  match r:
    case Fail{e}:
      Fail{e}
    case Done{rs}:
      Done{oks(rs, 0)}

def run_seq() -> IO(Unit):
  do IO<Unit>:
    r : Result<&1, &1, U32 & String, List<&2, HTTP.Response>> <- HTTP2.client.on_insecure(HOST(), PORT(), reqs())
    report(score_list(r))

def run_conc() -> IO(Unit):
  do IO<Unit>:
    r : Result<&1, &1, U32 & String, U32> <- HTTP2.client.concurrent_insecure(~h, HOST(), PORT(), reqs())
    report(r)

def pick(is_seq: Bool) -> IO(Unit):
  match is_seq:
    case True{}:
      run_seq()
    case False{}:
      run_conc()

def is_seq(xs: List<String>) -> Bool:
  match xs:
    case +m <> rest:
      String.eq(m, "seq")
    case Nil{}:
      False{}

def main() -> IO(Unit):
  do IO<Unit>:
    xs : List<String> <- IO.args()
    pick(is_seq(xs))
