# Big-body interop client (Phase 3 manual): POSTs 100 KB to the
# node:http2 echo server and checks the echo length. COMPILED LANES
# ONLY (native runtime faults past ~25 KB per transfer).
#
# Uses the httpx client lane (client.connect_insecure + client.request)
# instead of driving the H2 codec by hand: httpx renders :authority from
# the host and port, so the manual
# `H2.H2Hdr{":authority", "127.0.0.1:19892"}` this file used to build is
# gone (it was a workaround for an FID collision in the old
# lib/https.bend request_insecure, which no longer applies here).
# client.request is the single-request exchange and never closes: this file
# sends one request, closes the socket it dialed, in report.
#   node examples/https_server.js 19892 &
#   bend examples/httpx_big_client.bend -o /tmp/bigcli && /tmp/bigcli
import Base
import ../lib/tls.bend as TLS
import ../lib/httpx.bend as HTTPX

def body_big() -> List<&2, U32>:
  List.replicate(U32, 102400n, 65)

def report(out: Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt) -> IO(Unit):
  (s, r, st) = out
  match r:
    case Fail{(c, e)}:
      do IO<Unit>:
        x : Unit <- TLS.tls_close(s)
        y : Unit <- IO.print("FAIL POST " ++ U32.show(c) ++ " " ++ e)
        IO.die(Unit, 1, "")
    case Done{+resp}:
      match resp:
        case HTTPX.Response{+status, +headers, +body}:
          do IO<Unit>:
            x : Unit <- TLS.tls_close(s)
            y : Unit <- IO.print("STATUS " ++ U32.show(status))
            z : Unit <- IO.print("LEN " ++ U32.show(U32.from_nat(HTTPX.x_len(body))))
            q : Unit <- IO.print("DONE big")
            IO.die(Unit, 0, "")

def cli_conn(conn: Result<&1, &1, U32 & String, Socket & HTTPX.CliSt>) -> IO(Unit):
  match conn:
    case Fail{e}:
      do IO<Unit>:
        x : Unit <- IO.print("FAIL conn")
        IO.die(Unit, 1, "")
    case Done{value}:
      (sock, st) = value
      do IO<Unit>:
        out : Socket & Result<&1, &1, U32 & String, HTTPX.Response> & HTTPX.CliSt <-
          HTTPX.client.request(sock, st, "127.0.0.1", 19892,
            HTTPX.Request{"POST", "/echo", Nil{}, body_big()})
        report(out)

def main() -> IO(Unit):
  do IO<Unit>:
    conn : Result<&1, &1, U32 & String, Socket & HTTPX.CliSt> <- HTTPX.client.connect_insecure("127.0.0.1", 19892)
    cli_conn(conn)