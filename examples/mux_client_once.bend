# HTTPX once client for node:http2 interop (examples/mux_node_echoserv.js).
# Dials 127.0.0.1:19893 (the node H2-only echo server) with insecure TLS
# and POSTs "hello" via HTTPX.client.once_insecure; expects status 200 plus
# the same echo. Prints DONE n/n (manual only — not in check.sh).
# Usage: node examples/mux_node_echoserv.js 19893 1 &
#        bend examples/mux_client_once.bend
import Base
import ../lib/httpx.bend as HTTPX

def report_fail(label: String, c: U32, e: String) -> IO(Unit):
  do IO<Unit>:
    _ : Unit <- IO.print("FAIL " ++ label ++ " " ++ U32.show(c) ++ " " ++ e)
    IO.die(Unit, 1, "")

def report_bad(status: U32) -> IO(Unit):
  do IO<Unit>:
    _ : Unit <- IO.print("FAIL STATUS " ++ U32.show(status))
    IO.die(Unit, 1, "")

def report_echo(ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      do IO<Unit>:
        _ : Unit <- IO.print("OK ECHO")
        _ : Unit <- IO.print("DONE 3/3")
        IO.die(Unit, 0, "")
    case False{}:
      do IO<Unit>:
        _ : Unit <- IO.print("FAIL ECHO")
        IO.die(Unit, 1, "")

def report_resp_after(is_200: Bool, +body: List<&2, U32>, +status: U32) -> IO(Unit):
  match is_200:
    case True{}:
      do IO<Unit>:
        _ : Unit <- IO.print("OK STATUS")
        report_echo(U32.is_eq(HTTPX.x_eq(body, HTTPX.x_str_bytes("hello")), 1))
    case False{}:
      report_bad(status)

def report_resp(resp: HTTPX.Response) -> IO(Unit):
  match resp:
    case HTTPX.Response{+status, +headers, +body}:
      report_resp_after(U32.is_eq(status, 200), body, status)

def report(r: Result<&1, &1, U32 & String, HTTPX.Response>) -> IO(Unit):
  match r:
    case Fail{(c, e)}:
      report_fail("POST", c, e)
    case Done{+resp}:
      report_resp(resp)

def main() -> IO(Unit):
  do IO<Unit>:
    p : Unit <- IO.print("STEP dial")
    r : Result<&1, &1, U32 & String, HTTPX.Response> <- HTTPX.client.once_insecure("127.0.0.1", 19893, HTTPX.Request{"POST", "/echo", Nil{}, HTTPX.x_str_bytes("hello")})
    report(r)
