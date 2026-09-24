# Big-body interop client (Phase 3 manual): POSTs 100 KB to the
# node:http2 echo server and checks the echo length. COMPILED LANES
# ONLY (native runtime faults past ~25 KB per transfer). Uses the H2
# codec directly: HTTPS.request_insecure hits a pre-existing FID
# mangle collision (request.insecure vs request_insecure) when
# compiling to a binary.
#   node examples/https_server.js 19892 &
#   bend examples/https_big_client.bend -o /tmp/bigcli && /tmp/bigcli
import Base
import ../lib/tls.bend as TLS
import ../lib/http2.bend as H2

def body_big() -> List<&2, U32>:
  List.replicate(U32, 102400n, 65)

def report(got: Socket & Result<&1, &1, U32 & String, H2.H2Response>) -> IO(Unit):
  (s2, r) = got
  match r:
    case Fail{(c, e)}:
      do IO<Unit>:
        x : Unit <- TLS.tls_close(s2)
        y : Unit <- IO.print("FAIL POST " ++ U32.show(c) ++ " " ++ e)
        IO.die(Unit, 1, "")
    case Done{+resp}:
      match resp:
        case H2.H2Response{+status, +headers, +body}:
          do IO<Unit>:
            x : Unit <- TLS.tls_close(s2)
            y : Unit <- IO.print("STATUS " ++ U32.show(status))
            z : Unit <- IO.print("LEN " ++ U32.show(U32.from_nat(H2.b_len(body))))
            q : Unit <- IO.print("DONE big")
            IO.die(Unit, 0, "")

def cli_conn(conn: Result<&1, &1, U32 & String, Socket>) -> IO(Unit):
  match conn:
    case Fail{e}:
      do IO<Unit>:
        x : Unit <- IO.print("FAIL conn")
        IO.die(Unit, 1, "")
    case Done{sock}:
      do IO<Unit>:
        got : Socket & Result<&1, &1, U32 & String, H2.H2Response> <- H2.h2_request(sock, 1, "POST", "/echo", H2.H2Hdr{":authority", "127.0.0.1:19892"} <> Nil{}, body_big())
        report(got)

def main() -> IO(Unit):
  do IO<Unit>:
    conn : Result<&1, &1, U32 & String, Socket> <- H2.h2_connect_insecure("127.0.0.1", 19892)
    cli_conn(conn)
