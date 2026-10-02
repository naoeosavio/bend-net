# HTTPX request client for node:http2 interop
# (examples/mux_node_echoserv.js). Dials 127.0.0.1:19893 (the node
# H2-only echo server) with insecure TLS and POSTs "hello" via
# HTTPX.request_insecure (String in, String out); expects the same
# echo back. Prints DONE n/n (manual only — not in check.sh).
# Usage: node examples/mux_node_echoserv.js 19893 1 &
#        bend examples/httpx_request.bend
import Base
import ../lib/httpx.bend as HTTPX

def report_fail(label: String, c: U32, e: String) -> IO(Unit):
  do IO<Unit>:
    _ : Unit <- IO.print("FAIL " ++ label ++ " " ++ U32.show(c) ++ " " ++ e)
    IO.die(Unit, 1, "")

def report_echo(ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      do IO<Unit>:
        _ : Unit <- IO.print("OK ECHO")
        _ : Unit <- IO.print("DONE 2/2")
        IO.die(Unit, 0, "")
    case False{}:
      do IO<Unit>:
        _ : Unit <- IO.print("FAIL ECHO")
        IO.die(Unit, 1, "")

def report_text(+text: String) -> IO(Unit):
  report_echo(String.eq(text, "hello"))

def report(r: Result<&1, &1, U32 & String, String>) -> IO(Unit):
  match r:
    case Fail{(c, e)}:
      report_fail("POST", c, e)
    case Done{+text}:
      report_text(text)

def main() -> IO(Unit):
  do IO<Unit>:
    p : Unit <- IO.print("STEP dial")
    r : Result<&1, &1, U32 & String, String> <- HTTPX.request_insecure("127.0.0.1", 19893, "/echo", "POST", Nil{}, "hello")
    report(r)
