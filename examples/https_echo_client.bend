# HTTPS echo client for node:http2 interop (examples/https_server.js).
# Dials 127.0.0.1:19892 (the node:http2 server) with insecure TLS and
# POSTs "hello"; expects the echo. Prints DONE n/n (manual only —
# not in check.sh). If the Node server HPACK-encodes huffman, Bend
# answers 502 huffman refused (documented limitation).
#   bend examples/https_echo_client.bend
import Base
import ../lib/https.bend as HTTPS
import ../lib/http2.bend as H2

def report_fail(label: String, c: U32, e: String) -> IO(Unit):
  do IO<Unit>:
    _ : Unit <- IO.print("FAIL " ++ label ++ " " ++ U32.show(c) ++ " " ++ e)
    IO.die(Unit, 1, "")

def report_done(body: String) -> IO(Unit):
  match body:
    case SCon{Chr{104}, SCon{Chr{101}, SCon{Chr{108}, SCon{Chr{108}, SCon{Chr{111}, SNil{}}}}}}:
      do IO<Unit>:
        _ : Unit <- IO.print("OK ECHO")
        _ : Unit <- IO.print("DONE 3/3")
        IO.die(Unit, 0, "")
    case rest:
      do IO<Unit>:
        _ : Unit <- IO.print("FAIL ECHO " ++ String.take(rest, 80n))
        IO.die(Unit, 1, "")

def report(r: Result<&1, &1, U32 & String, String>) -> IO(Unit):
  match r:
    case Fail{(c, e)}:
      report_fail("POST", c, e)
    case Done{body}:
      report_done(body)

def main() -> IO(Unit):
  do IO<Unit>:
    p : Unit <- IO.print("STEP dial")
    r : Result<&1, &1, U32 & String, String> <- HTTPS.send_request_insecure("127.0.0.1", 19892, "/echo", "POST", Nil{}, "hello")
    report(r)
