# lib (lib_hpack_continuation): Phase 4 HTTP/2 header-block continuation.
# Pure checks cover the new classifiers (needs_cont / cont_ok /
# cont_cls, client + server classify incl. fresh-only SETTINGS/PING),
# the wire-helper shapes (RST/GOAWAY payloads), client HPACK table
# threading (st_hp) and a >16KB header block split into HEADERS +
# CONTINUATION, decoded on both sides (client H2Head, server
# H2ReqHead). The IO part is a loopback where a canned peer answers
# with a split HEADERS + CONTINUATION block, proving the client
# reassembly on the wire. Big request headers against server_on ride
# the manual Node matrix (the mux path is Phase 5).
import Base
import ../../lib/tls.bend as TLS
import ../../lib/http2.bend as H2

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

def is_false(ok: Bool) -> U32:
  match ok:
    case True{}:
      0
    case False{}:
      1

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

def chk_needs() -> U32:
  (b2u(H2.h2_needs_cont(1, 1)) + is_false(H2.h2_needs_cont(1, 4)) + is_false(H2.h2_needs_cont(0, 0)) : U32)

def chk_cont_ok() -> U32:
  (b2u(H2.h2_cont_ok(9, 1, 1)) + is_false(H2.h2_cont_ok(9, 1, 3)) + is_false(H2.h2_cont_ok(9, 0, 0)) + is_false(H2.h2_cont_ok(1, 1, 1)) : U32)

def chk_cls() -> U32:
  (b2u(U32.is_eq(H2.h2_cont_cls_of(9, 1, 1, 4), 0)) + b2u(U32.is_eq(H2.h2_cont_cls_of(9, 1, 1, 0), 1)) + b2u(U32.is_eq(H2.h2_cont_cls_of(0, 1, 1, 0), 2)) + b2u(U32.is_eq(H2.h2_cont_cls_of(9, 3, 1, 4), 2)) : U32)

def chk_classify() -> U32:
  (b2u(U32.is_eq(H2.h2_resp.classify(H2.H2Frame{3, 0, 1, Nil{}}, 1), 7))
   + b2u(U32.is_eq(H2.h2_resp.classify(H2.H2Frame{9, 4, 1, Nil{}}, 1), 8))
   + b2u(U32.is_eq(H2.h2_resp.classify(H2.H2Frame{7, 0, 0, [0, 0, 0, 0, 0, 0, 0, 0]}, 1), 5))
   + b2u(U32.is_eq(H2.h2_resp.classify(H2.H2Frame{6, 0, 0, [1, 2, 3, 4, 5, 6, 7, 8]}, 1), 4))
   + b2u(U32.is_eq(H2.h2_resp.classify(H2.H2Frame{4, 0, 0, Nil{}}, 1), 1))
   + b2u(U32.is_eq(H2.h2_resp.classify(H2.H2Frame{4, 1, 0, Nil{}}, 1), 0))
   + b2u(U32.is_eq(H2.h2_srv.classify(H2.H2Frame{3, 0, 1, [0, 0, 0, 8]}), 2))
   + b2u(U32.is_eq(H2.h2_srv.classify(H2.H2Frame{9, 0, 1, [7]}), 8))
   + b2u(U32.is_eq(H2.h2_srv.classify(H2.H2Frame{6, 0, 0, [1, 2, 3, 4, 5, 6, 7, 8]}), 4)) : U32)

def pads_go(+n: Nat, acc: List<&2, H2.H2Hdr>) -> List<&2, H2.H2Hdr>:
  match n:
    case 0n:
      acc
    case 1n+m:
      pads_go(m, H2.H2Hdr{"x-pad", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} <> acc)

def pads() -> List<&2, H2.H2Hdr>:
  pads_go(160n, Nil{})

def big_block() -> List<&2, U32>:
  H2.hpack_block(List.append(&2, H2.H2Hdr, [H2.H2Hdr{":method", "GET"}, H2.H2Hdr{":path", "/big"}, H2.H2Hdr{":status", "200"}], pads()))

def big_first() -> List<&2, U32>:
  H2.b_take(16384n, big_block())

def big_rest() -> List<&2, U32>:
  H2.b_drop(16384n, big_block())

def big_combined() -> List<&2, U32>:
  H2.b_append(big_first(), big_rest())

def status_of(r: Result<&1, &1, U32 & String, H2.H2Head>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{+h}:
      match h:
        case H2.H2Head{+status, +headers}:
          status

def method_ok(r: Result<&1, &1, U32 & String, H2.H2ReqHead & H2.HpDyn>) -> U32:
  match r:
    case Fail{e}:
      0
    case Done{(+rh, +tab)}:
      match rh:
        case H2.H2ReqHead{+method, +path, +headers}:
          b2u(String.eq(method, "GET"))

def chk_big() -> U32:
  (b2u(Nat.is_lt(16384n, H2.b_len(big_block())))
   + bytes_eq(big_combined(), big_block())
   + b2u(U32.is_eq(status_of(H2.h2_head.of(H2.h2_head.decode(big_combined(), H2.hp_empty()))), 200))
   + method_ok(H2.h2_reqhead.decode(big_combined(), H2.hp_empty())) : U32)

def hp_max(+t: H2.HpDyn) -> U32:
  match t:
    case H2.HpDyn{ents, size, max}:
      max

def chk_st_hp() -> U32:
  b2u(U32.is_eq(hp_max(H2.h2_resp.st_hp(H2.H2RespSt{None{}, Nil{}, H2.hp_empty()})), 4096))

def chk_wire() -> U32:
  (b2u(Nat.is_eq(H2.b_len(H2.h2_rst_pay(8)), 4n)) + b2u(Nat.is_eq(H2.b_len(H2.h2_goaway_pay(1, 0)), 8n)) : U32)

def pure_sum() -> U32:
  (chk_needs() + chk_cont_ok() + chk_cls() + chk_classify() + chk_big() + chk_st_hp() + chk_wire() : U32)

# Canned peer: reads preface + SETTINGS + HEADERS + DATA with the
# frame reader, then answers with a split block (HEADERS without
# END_HEADERS, CONTINUATION with END_HEADERS) plus DATA "hi".
def cont_send(prev: Socket & Result<&1, &1, (U32 & String), Unit>, +typ: U32, +flags: U32, +sid: U32, +pay: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, (U32 & String), Unit>):
  (s, r) = prev
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, (U32 & String), Unit>, (s, Fail{e}))
    case Done{u}:
      H2.h2_send_frame(s, typ, flags, sid, pay)

def srv_send_resp(sock: Socket) -> IO(Socket & Result<&1, &1, (U32 & String), Unit>):
  do IO<Socket & Result<&1, &1, (U32 & String), Unit>>:
    first : List<&2, U32> = H2.b_take(10n, H2.hpack_block([H2.H2Hdr{":status", "200"}]))
    second : List<&2, U32> = H2.b_drop(10n, H2.hpack_block([H2.H2Hdr{":status", "200"}]))
    a0 : Socket & Result<&1, &1, (U32 & String), Unit> <- H2.h2_send_frame(sock, 4, 0, 0, H2.h2_settings_initial_pay())
    a1 : Socket & Result<&1, &1, (U32 & String), Unit> <- cont_send(a0, 1, 0, 1, first)
    a2 : Socket & Result<&1, &1, (U32 & String), Unit> <- cont_send(a1, 9, 4, 1, second)
    cont_send(a2, 0, 1, 1, [104, 105])

def srv_fail(sock: Socket) -> IO(String):
  do IO<String>:
    x : Unit <- TLS.tls_close(sock)
    return "down"

def srv_done(sent: Socket & Result<&1, &1, (U32 & String), Unit>) -> IO(String):
  (s, r) = sent
  match r:
    case Fail{e}:
      srv_fail(s)
    case Done{u}:
      do IO<String>:
        x : Unit <- TLS.tls_close(s)
        return "up"

def srv_send_after(prev: Socket & H2.H2Got) -> IO(Socket & Result<&1, &1, (U32 & String), Unit>):
  (s, g) = prev
  match g:
    case H2.H2GotOk{frame, buf}:
      srv_send_resp(s)
    case H2.H2GotErr{code, msg}:
      IO.pure(Socket & Result<&1, &1, (U32 & String), Unit>, (s, Fail{(code, msg)}))

def srv_next(prev: Socket & H2.H2Got) -> IO(Socket & H2.H2Got):
  (s, g) = prev
  match g:
    case H2.H2GotOk{+frame, +buf}:
      H2.h2_read_frame(s, buf)
    case H2.H2GotErr{code, msg}:
      IO.pure(Socket & H2.H2Got, (s, H2.H2GotErr{code, msg}))

def canned_frames(g0: Socket & H2.H2Got) -> IO(String):
  do IO<String>:
    g1 : Socket & H2.H2Got <- srv_next(g0)
    g2 : Socket & H2.H2Got <- srv_next(g1)
    resp : Socket & Result<&1, &1, (U32 & String), Unit> <- srv_send_after(g2)
    srv_done(resp)

def canned_magic(sock: Socket, +chunk: List<&2, U32>, +magic: U32) -> IO(String):
  match magic:
    case 1:
      do IO<String>:
        g0 : Socket & H2.H2Got <- H2.h2_read_frame(sock, H2.b_drop(24n, chunk))
        canned_frames(g0)
    case _:
      srv_fail(sock)

def canned_retry(r2: Socket & Result<&1, &1, (U32 & String), List<&2, U32>>, +chunk: List<&2, U32>) -> IO(String):
  (s2, r) = r2
  match r:
    case Fail{e}:
      srv_fail(s2)
    case Done{+c2}:
      canned_magic(s2, H2.b_append(chunk, c2), H2.h2_srv.preface_ok(H2.b_append(chunk, c2)))

def canned_chunk(sock: Socket, +chunk: List<&2, U32>, +n: Nat, enough: Bool) -> IO(String):
  match enough:
    case True{}:
      canned_magic(sock, chunk, H2.h2_srv.preface_ok(chunk))
    case False{}:
      do IO<String>:
        r2 : Socket & Result<&1, &1, (U32 & String), List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
        canned_retry(r2, chunk)

def canned_pref(r1: Socket & Result<&1, &1, (U32 & String), List<&2, U32>>) -> IO(String):
  (s1, r) = r1
  match r:
    case Fail{e}:
      srv_fail(s1)
    case Done{+chunk}:
      canned_chunk(s1, chunk, H2.b_len(chunk), Nat.is_ge(H2.b_len(chunk), 24n))

def canned_talk(sock: Socket) -> IO(String):
  do IO<String>:
    r1 : Socket & Result<&1, &1, (U32 & String), List<&2, U32>> <- TLS.tls_recv_bytes(sock, 16384)
    canned_pref(r1)

law server_conn:
  for m: Listener & Result<&1, &1, (U32 & String), Socket>
  IO(String)

def server_conn(m):
  (l, r) = m
  match r:
    case Fail{e}:
      do IO<String>:
        x : Unit <- Listener.close(l)
        return "down"
    case Done{sock}:
      do IO<String>:
        out : String <- canned_talk(sock)
        x : Unit <- Listener.close(l)
        return out

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    m : Listener & Result<&1, &1, (U32 & String), Socket> <- TLS.tls_accept(l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    server_conn(m)

def client_done(acc: U32, got: Socket & Result<&1, &1, (U32 & String), H2.H2Response>) -> IO(U32):
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
            x : Unit <- TLS.tls_close(s2)
            +ok : U32 = (b2u(U32.is_eq(status, 200)) + bytes_eq(body, [104, 105]) : U32)
            return (acc + ok : U32)

def client_conn(conn: Result<&1, &1, (U32 & String), Socket>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        got : Socket & Result<&1, &1, (U32 & String), H2.H2Response> <- H2.h2_request(sock, 1, "GET", "/", Nil{}, Nil{})
        client_done(0, got)

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
    +up : U32 = b2u(String.eq(s, "up"))
    +total : U32 = (a + up + pure_sum() : U32)
    w : Unit <- IO.print(U32.show(total))
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 18520)
    main_go(b)

#|30
