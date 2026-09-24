# lib (lib_h2_rst): Phase 4 RST_STREAM + GOAWAY.
# Pure checks pin the new classifiers (client RST/CONT/GOAWAY,
# server RST/CONT/PING), the reset ledger (connection HPACK table
# survives) and the wire shapes (RST code, GOAWAY last-sid/code).
# The IO part is a loopback: the client aborts stream 1 with
# RST_STREAM, completes stream 3 on the same connection (the abort
# must not tear the connection down), then sends GOAWAY; the server
# answers stream 3 and ends the GOAWAY turn gracefully (Done, not
# Fail). Full multiplexed reset semantics await the Phase 5 mux.
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

def chk_classify() -> U32:
  (b2u(U32.is_eq(H2.h2_resp.classify(H2.H2Frame{3, 0, 1, [0, 0, 0, 8]}, 1), 7))
   + b2u(U32.is_eq(H2.h2_resp.classify(H2.H2Frame{9, 4, 1, [1, 2, 3]}, 1), 8))
   + b2u(U32.is_eq(H2.h2_resp.classify(H2.H2Frame{7, 0, 0, [0, 0, 0, 0, 0, 0, 0, 0]}, 1), 5))
   + b2u(U32.is_eq(H2.h2_srv.classify(H2.H2Frame{3, 0, 1, [0, 0, 0, 8]}), 2))
   + b2u(U32.is_eq(H2.h2_srv.classify(H2.H2Frame{9, 0, 1, [1, 2, 3]}), 8))
   + b2u(U32.is_eq(H2.h2_srv.classify(H2.H2Frame{6, 0, 0, [9, 9, 9, 9, 9, 9, 9, 9]}), 4)) : U32)

def hp_max(+t: H2.HpDyn) -> U32:
  match t:
    case H2.HpDyn{ents, size, max}:
      max

def chk_reset() -> U32:
  b2u(U32.is_eq(hp_max(H2.h2_srv.st_hp(H2.h2_srv.rst_reset(H2.H2SrvSt{None{}, Nil{}, 7, H2.hp_empty()}))), 4096))

def chk_wire() -> U32:
  (bytes_eq(H2.h2_rst_pay(8), [0, 0, 0, 8])
   + bytes_eq(H2.b_take(4n, H2.h2_goaway_pay(3, 1)), [0, 0, 0, 3])
   + bytes_eq(H2.b_drop(4n, H2.h2_goaway_pay(3, 1)), [0, 0, 0, 1]) : U32)

def pure_sum() -> U32:
  (chk_classify() + chk_reset() + chk_wire() : U32)

def h2_echo(req: H2.H2Request) -> IO(H2.H2Response):
  match req:
    case H2.H2Request{+method, +path, +headers, +body}:
      IO.pure(H2.H2Response, H2.H2Response{200, Nil{}, body})

def server_down(l: Listener, e: U32 & String) -> IO(String):
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

def raw_rst(prev: Socket & Result<&1, &1, (U32 & String), Unit>, +sid: U32) ->
  IO(Socket & Result<&1, &1, (U32 & String), Unit>):
  (s, r) = prev
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, (U32 & String), Unit>, (s, Fail{e}))
    case Done{u}:
      H2.h2_send_rst(s, sid, 8)

def client_req(prev: Socket & Result<&1, &1, (U32 & String), Unit>) ->
  IO(Socket & Result<&1, &1, (U32 & String), H2.H2Response>):
  (s, r) = prev
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, (U32 & String), H2.H2Response>, (s, Fail{e}))
    case Done{u}:
      H2.h2_request(s, 3, "POST", "/echo", Nil{}, [112, 105, 110, 103])

def client_closed(+acc: U32, sent: Socket & Result<&1, &1, (U32 & String), Unit>) -> IO(U32):
  (s, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s)
        return acc
    case Done{u}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s)
        return acc

def client_bye(acc: U32, got: Socket & Result<&1, &1, (U32 & String), H2.H2Response>) -> IO(U32):
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
            +ok : U32 = (b2u(U32.is_eq(status, 200)) + bytes_eq(body, [112, 105, 110, 103]) : U32)
            sent : Socket & Result<&1, &1, (U32 & String), Unit> <- H2.h2_send_goaway(s2, 3, 0)
            client_closed((acc + ok : U32), sent)

def client_conn(conn: Result<&1, &1, (U32 & String), Socket>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      do IO<U32>:
        a0 : Socket & Result<&1, &1, (U32 & String), Unit> <- H2.h2_send_frame(sock, 1, 4, 1, H2.h2_request.head("POST", "/rst", Nil{}))
        a1 : Socket & Result<&1, &1, (U32 & String), Unit> <- raw_rst(a0, 1)
        got : Socket & Result<&1, &1, (U32 & String), H2.H2Response> <- client_req(a1)
        client_bye(0, got)

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
    b : Listener & U32 <- listen_any(32n, 18560)
    main_go(b)

#|13
