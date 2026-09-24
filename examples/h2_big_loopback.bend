# Big-body loopback (Phase 3 manual): Bend<->Bend 100 KB echo on one
# stream, exercising the chunked sender (7 DATA frames) and the
# data_run overflow tails. COMPILED LANES ONLY — the native runtime
# faults past ~25 KB per transfer, so this never runs in check.sh
# (examples are check-only there):
#   bend examples/h2_big_loopback.bend -o /tmp/biglb && /tmp/biglb
#   bend examples/h2_big_loopback.bend -o /tmp/biglb.js && bun /tmp/biglb.js
import Base
import ../lib/tls.bend as TLS
import ../lib/http2.bend as H2

def body_big() -> List<&2, U32>:
  List.replicate(U32, 102400n, 65)

def mul_eq(+acc: U32, same: Bool) -> U32:
  match same:
    case True{}:
      acc
    case False{}:
      0

def bytes_eq(a: List<&2, U32>, b: List<&2, U32>) -> U32:
  match a b:
    case Nil{} Nil{}:
      1
    case h1 <> t1 h2 <> t2:
      mul_eq(bytes_eq(t1, t2), U32.is_eq(h1, h2))
    case _ _:
      0

def h2_echo(req: H2.H2Request) -> IO(H2.H2Response):
  match req:
    case H2.H2Request{+method, +path, +headers, +body}:
      IO.pure(H2.H2Response, H2.H2Response{200, Nil{}, body})

def show_fail(tag: String, e: U32 & String) -> IO(Unit):
  (c, m) = e
  do IO<Unit>:
    x : Unit <- IO.print(tag ++ " FAIL " ++ U32.show(c) ++ " " ++ m)
    return x

def srv_drained(got2: Socket & Result<&1, &1, (U32 & String), Unit> & H2.HpDyn) -> IO(String):
  (s3, r3, tab3) = got2
  match r3:
    case Fail{e}:
      do IO<String>:
        x : Unit <- TLS.tls_close(s3)
        y : Unit <- IO.print("srv ok")
        return "srv ok"
    case Done{u}:
      do IO<String>:
        x : Unit <- TLS.tls_close(s3)
        y : Unit <- IO.print("srv extra")
        return "srv extra"

def srv_drain(s2: Socket, tab: H2.HpDyn) -> IO(String):
  do IO<String>:
    got2 : Socket & Result<&1, &1, (U32 & String), Unit> & H2.HpDyn <- H2.h2_serve_next(s2, h2_echo, tab)
    srv_drained(got2)

def srv_done(got: Socket & Result<&1, &1, (U32 & String), Unit> & H2.HpDyn) -> IO(String):
  (s2, r, tab) = got
  match r:
    case Fail{e}:
      do IO<String>:
        x : Unit <- TLS.tls_close(s2)
        y : Unit <- show_fail("srv", e)
        return "srv fail"
    case Done{u}:
      srv_drain(s2, tab)

def srv_go(sock: Socket) -> IO(String):
  do IO<String>:
    got : Socket & Result<&1, &1, (U32 & String), Unit> & H2.HpDyn <- H2.h2_serve_once(sock, h2_echo)
    srv_done(got)

def srv_accept(m: Listener & Result<&1, &1, (U32 & String), Socket>) -> IO(String):
  (l, r) = m
  match r:
    case Fail{e}:
      do IO<String>:
        x : Unit <- Listener.close(l)
        return "accept fail"
    case Done{sock}:
      do IO<String>:
        s : String <- srv_go(sock)
        y : Unit <- Listener.close(l)
        return s

def server_side(l: Listener) -> IO(String):
  do IO<String>:
    m : Listener & Result<&1, &1, (U32 & String), Socket> <- TLS.tls_accept(l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    srv_accept(m)

def cli_done(got: Socket & Result<&1, &1, (U32 & String), H2.H2Response>) -> IO(U32):
  (s2, r) = got
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s2)
        y : Unit <- show_fail("cli", e)
        return 0
    case Done{+resp}:
      match resp:
        case H2.H2Response{+status, +headers, +body}:
          do IO<U32>:
            x : Unit <- TLS.tls_close(s2)
            +n : U32 = U32.from_nat(H2.b_len(body))
            y : Unit <- IO.print(U32.show(n))
            z : Unit <- IO.print(U32.show(bytes_eq(body, body_big())))
            return n

def cli_conn(conn: Result<&1, &1, (U32 & String), Socket>) -> IO(U32):
  match conn:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- IO.print("FAIL conn")
        return 0
    case Done{sock}:
      do IO<U32>:
        got : Socket & Result<&1, &1, (U32 & String), H2.H2Response> <- H2.h2_request(sock, 1, "POST", "/echo", Nil{}, body_big())
        cli_done(got)

def client(port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, (U32 & String), Socket> <- H2.h2_connect_insecure("127.0.0.1", port)
    cli_conn(conn)

def with_chan(chan: Chan(String), a: U32) -> IO(U32):
  do IO<U32>:
    s : String <- IO.join(String, chan)
    x : Unit <- IO.print(s)
    return a

def main_go(b: Listener & U32) -> IO(U32):
  (l, port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    a : U32 <- client(port)
    with_chan(chan, a)

def listen_done(r: Result<&1, &1, (U32 & String), Listener>, port: U32) -> IO(U32):
  match r:
    case Fail{e}:
      IO.die(U32, 1, "listen")
    case Done{l}:
      main_go((l, port))

def main() -> IO(U32):
  do IO<U32>:
    r : Result<&1, &1, (U32 & String), Listener> <- TCP.listen(18611)
    listen_done(r, 18611)
