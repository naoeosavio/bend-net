# lib (lib_h2_flow): Phase 3 HTTP/2 flow units + loopback.
# Pure checks cover the new SETTINGS ledger (initial payload shape,
# peer apply incl. unknown-id ignore), WINDOW_UPDATE validation and
# PADDED/PRIORITY stripping. The IO part echoes a 20 KB body (two
# DATA frames each way: 16384 + 4096 + closing empty) on two
# sequential streams of one TLS connection, proving the chunked
# sender and multi-DATA reassembly Bend<->Bend. Bigger bodies
# (100 KB, tail loop) ride compiled lanes only: the native runtime
# faults past ~25 KB per transfer (see task-020 Discoveries).
import Base
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as H2

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

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

def body1() -> List<&2, U32>:
  List.replicate(U32, 20480n, 65)

def body2() -> List<&2, U32>:
  List.replicate(U32, 10240n, 66)

def chk_init_pay() -> U32:
  b2u(Nat.is_eq(H2.b_len(H2.h2_settings_initial_pay()), 12n))

def chk_apply_iw.go(+s: H2.H2Settings) -> U32:
  match s:
    case H2.H2Settings{mf, iw, mhl, mcc, hts}:
      b2u(U32.is_eq(iw, 6291456))

def chk_apply_iw() -> U32:
  chk_apply_iw.go(H2.h2_settings_apply([0, 4, 0, 96, 0, 0], H2.h2_settings_default()))

def chk_apply_mf.go(+s: H2.H2Settings) -> U32:
  match s:
    case H2.H2Settings{mf, iw, mhl, mcc, hts}:
      b2u(U32.is_eq(mf, 65535))

def chk_apply_mf() -> U32:
  chk_apply_mf.go(H2.h2_settings_apply([0, 5, 0, 0, 255, 255], H2.h2_settings_default()))

def chk_apply_unknown.go(+s: H2.H2Settings) -> U32:
  match s:
    case H2.H2Settings{mf, iw, mhl, mcc, hts}:
      b2u(U32.is_eq(mf, 16384))

def chk_apply_unknown() -> U32:
  chk_apply_unknown.go(H2.h2_settings_apply([0, 9, 0, 0, 0, 1], H2.h2_settings_default()))

def chk_wu_ok() -> U32:
  b2u(H2.h2_window_update_ok([0, 0, 0, 1]))

def chk_is_false(ok: Bool) -> U32:
  match ok:
    case True{}:
      0
    case False{}:
      1

def chk_wu_zero() -> U32:
  chk_is_false(H2.h2_window_update_ok([0, 0, 0, 0]))

def chk_wu_short() -> U32:
  chk_is_false(H2.h2_window_update_ok([1, 2, 3]))

def chk_strip_pad() -> U32:
  bytes_eq(H2.h2_frame_payload([2, 65, 66, 0, 0], 8, 0), [65, 66])

def chk_strip_prio() -> U32:
  bytes_eq(H2.h2_frame_payload([1, 2, 3, 4, 5, 65], 32, 1), [65])

def pure_sum() -> U32:
  (chk_init_pay() + chk_apply_iw() + chk_apply_mf() + chk_apply_unknown() + chk_wu_ok() + chk_wu_zero() + chk_wu_short() + chk_strip_pad() + chk_strip_prio() : U32)

def h2_echo(req: H2.H2Request) -> IO(H2.H2Response):
  match req:
    case H2.H2Request{+method, +path, +headers, +body}:
      IO.pure(H2.H2Response, H2.H2Response{200, Nil{}, body})

law server_down:
  for l: Listener
  for e: U32 & String
  IO(String)

def server_down(l, e):
  do IO<String>:
    x : Unit <- Listener.close(l)
    return "down"

def server_close(l: Listener, s2: Socket) -> IO(String):
  do IO<String>:
    x : Unit <- TLS.tls_close(s2)
    y : Unit <- Listener.close(l)
    return "up"

def server_served2(l: Listener, got: Socket & Result<&1, &1, (U32 & String), Unit> & H2.HpDyn) -> IO(String):
  (s2, r, tab) = got
  match r:
    case Fail{e}:
      do IO<String>:
        x : Unit <- TLS.tls_close(s2)
        server_down(l, e)
    case Done{u}:
      server_close(l, s2)

def server_serve2(sock: Socket, +tab: H2.HpDyn) -> IO(Socket & Result<&1, &1, (U32 & String), Unit> & H2.HpDyn):
  H2.h2_serve_next(sock, h2_echo, tab)

def server_served(l: Listener, got: Socket & Result<&1, &1, (U32 & String), Unit> & H2.HpDyn) -> IO(String):
  (s2, r, tab) = got
  match r:
    case Fail{e}:
      do IO<String>:
        x : Unit <- TLS.tls_close(s2)
        server_down(l, e)
    case Done{u}:
      do IO<String>:
        got2 : Socket & Result<&1, &1, (U32 & String), Unit> & H2.HpDyn <- server_serve2(s2, tab)
        server_served2(l, got2)

def server_serve(sock: Socket) -> IO(Socket & Result<&1, &1, (U32 & String), Unit> & H2.HpDyn):
  H2.h2_serve_once(sock, h2_echo)

law server_talk:
  for l: Listener
  for sock: Socket
  IO(String)

def server_talk(l, sock):
  do IO<String>:
    got : Socket & Result<&1, &1, (U32 & String), Unit> & H2.HpDyn <- server_serve(sock)
    server_served(l, got)

law server_conn:
  for m: Listener & Result<&1, &1, (U32 & String), Socket>
  IO(String)

def server_conn(m):
  (l, r) = m
  match r:
    case Fail{e}:
      server_down(l, e)
    case Done{sock}:
      server_talk(l, sock)

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    m : Listener & Result<&1, &1, (U32 & String), Socket> <- TLS.tls_accept(l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    server_conn(m)

def client_score2(sock: Socket, body: List<&2, U32>, st_ok: U32, acc: U32) -> IO(U32):
  do IO<U32>:
    x : Unit <- TLS.tls_close(sock)
    +eq : U32 = bytes_eq(body, body2())
    return (st_ok * eq + acc : U32)

def client_done2(acc: U32, got: Socket & Result<&1, &1, (U32 & String), H2.H2Response>) -> IO(U32):
  (s2, r) = got
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s2)
        return acc
    case Done{+resp}:
      match resp:
        case H2.H2Response{+status, +headers, +body}:
          client_score2(s2, body, b2u(U32.is_eq(status, 200)), acc)

def client_second(acc: U32, got: Socket & Result<&1, &1, (U32 & String), H2.H2Response>) -> IO(U32):
  (s2, r) = got
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s2)
        return acc
    case Done{+resp}:
      match resp:
        case H2.H2Response{+status, +headers, +body}:
          do IO<U32>:
            +ok1 : U32 = (b2u(U32.is_eq(status, 200)) * bytes_eq(body, body1()) : U32)
            got2 : Socket & Result<&1, &1, (U32 & String), H2.H2Response> <- H2.h2_request(s2, 3, "POST", "/echo", Nil{}, body2())
            client_done2((acc + ok1 : U32), got2)

def client_conn(conn: Result<&1, &1, (U32 & String), Socket>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        got : Socket & Result<&1, &1, (U32 & String), H2.H2Response> <- H2.h2_request(sock, 1, "POST", "/echo", Nil{}, body1())
        client_second(0, got)

law client:
  for port: U32
  IO(U32)

def client(port):
  do IO<U32>:
    conn : Result<&1, &1, (U32 & String), Socket> <- H2.h2_connect_insecure("127.0.0.1", port)
    client_conn(conn)

law listen_retry:
  for port: U32
  for r: Result<&1, &1, (U32 & String), Listener>
  for rest: IO(Listener & U32)
  IO(Listener & U32)

def listen_retry(port, r, rest):
  match r:
    case Done{l}:
      IO.pure(Listener & U32, (l, port))
    case Fail{e}:
      rest

law listen_any:
  for tries: Nat
  for +port: U32
  IO(Listener & U32)

def listen_any(tries, port):
  match tries:
    case 0n:
      IO.die(Listener & U32, 1, "no free tcp port")
    case 1n+t:
      rest = listen_any(t, (port + 1 : U32))
      do IO<Listener & U32>:
        r : Result<&1, &1, (U32 & String), Listener> <- TCP.listen(port)
        listen_retry(port, r, rest)

law main_go:
  for b: Listener & U32
  IO(U32)

def main_go(b):
  (l, port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server_side(l))
    +a : U32 <- client(port)
    s : String <- IO.join(String, chan)
    +total : U32 = (a + pure_sum() : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 18460)
    main_go(b)

#|11
