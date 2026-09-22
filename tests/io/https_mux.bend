# lib (lib_https_mux): truly interleaved streams on one HTTPS
# connection against HTTPS.server_on_concurrent's mux. The client
# pipelines HEADERS(1), HEADERS(3), DATA(1,END), DATA(3,END) raw; the
# server must answer 3 while 1 is still open (a sequential server
# would corrupt stream 1's state). The handler answers 200 with an
# empty body, so responses are HEADERS(END_STREAM) only; the client
# collects both heads and checks both statuses. Golden 1.
import Base
import ../../lib/tls.bend as TLS
import ../../lib/https.bend as HTTPS
import ../../lib/http2.bend as H2

def body1() -> List<&2, U32>:
  [104, 101, 108, 108, 111]

def body2() -> List<&2, U32>:
  [119, 111, 114, 108, 100, 33]

def mux_ok(req: H2.H2Request) -> IO(H2.H2Response):
  match req:
    case H2.H2Request{+method, +path, +headers, +body}:
      IO.pure(H2.H2Response, H2.H2Response{200, Nil{}, Nil{}})

# Client collect: gather HEADERS for sid 1 and 3 (handler answers 200
# with empty bodies, so no DATA is ever read). Score is 1 iff both
# decoded with :status 200. One @unsafe self-recursive def; each phase
# carries at most one single match; slot decisions ride leaf calls.

def coll.score(h1: Maybe<&2, H2.H2Head>, h3: Maybe<&2, H2.H2Head>) -> U32:
  match h1 h3:
    case Some{H2.H2Head{200, _}} Some{H2.H2Head{200, _}}:
      1
    case _ _:
      0

def coll.hd_ok(dec: Result<&1, &1, U32 & String, H2.H2Head>) -> Bool:
  match dec:
    case Fail{e}:
      False{}
    case Done{h}:
      True{}

def coll.head_of(dec: Result<&1, &1, U32 & String, H2.H2Head>) -> H2.H2Head:
  match dec:
    case Fail{e}:
      H2.H2Head{0, Nil{}}
    case Done{+h}:
      h

def coll.slotH(ok: Bool, +h: H2.H2Head, +old: Maybe<&2, H2.H2Head>, isX: Bool) -> Maybe<&2, H2.H2Head>:
  match ok isX:
    case True{} True{}:
      Some{h}
    case _ _:
      old

def coll.slotD(ok: Bool, +d: Bool, +e: U32, isX: Bool) -> Bool:
  match ok e isX:
    case True{} 1 True{}:
      True{}
    case _ _ _:
      d

def coll.done2(+d1: Bool, +d3: Bool) -> Bool:
  match d1 d3:
    case True{} True{}:
      True{}
    case _ _:
      False{}

def coll.acked(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & H2.H2Got:
  (s2, r) = sent
  match r:
    case Fail{e}:
      (s2, H2.H2GotErr{616, "tls io"})
    case Done{u}:
      (s2, H2.H2GotErr{0, "next"})

def coll.ack(got: Socket & H2.H2Got) -> IO(Socket & H2.H2Got):
  (s, g) = got
  do IO<Socket & H2.H2Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- H2.h2_send_frame(s, H2.h2_t_settings(), H2.h2_f_ack(), 0, Nil{})
    IO.pure(Socket & H2.H2Got, coll.acked(sent))

def coll.done_got(got: Socket & H2.H2Got, h1: Maybe<&2, H2.H2Head>, h3: Maybe<&2, H2.H2Head>) -> Socket & U32:
  (s, g) = got
  (s, coll.score(h1, h3))

# SETTINGS action codes: 0 skip, 1 ack, 2 HEADERS route. An ACK frame
# (typ 4 + ACK flag) is skipped, never acked back: two unbounded read
# loops would ping-pong SETTINGS ACKs forever otherwise.

def coll.setact(+typ: U32, +flags: U32) -> U32:
  match typ flags:
    case 4 1:
      0
    case 4 _:
      1
    case 1 _:
      2
    case _ _:
      0

@unsafe
def coll(phase: U32, got: Socket & H2.H2Got, h1: Maybe<&2, H2.H2Head>, h3: Maybe<&2, H2.H2Head>, +d1: Bool, +d3: Bool, fin: Bool, +buf: List<&2, U32>, typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +h: H2.H2Head, +okH: Bool, +e01: U32) ->
  IO(Socket & U32):
  match phase:
    case 0:
      match fin:
        case True{}:
          IO.pure(Socket & U32, coll.done_got(got, h1, h3))
        case False{}:
          coll(1, got, h1, h3, d1, d3, fin, buf, 0, 0, 0, Nil{}, H2.H2Head{0, Nil{}}, False{}, 0)
    case 1:
      (s1, g1) = got
      match g1:
        case H2.H2GotErr{code, msg}:
          match code:
            case 0:
              do IO<Socket & U32>:
                got2 : Socket & H2.H2Got <- H2.h2_read_frame(s1, buf)
                coll(1, got2, h1, h3, d1, d3, fin, buf, 0, 0, 0, Nil{}, H2.H2Head{0, Nil{}}, False{}, 0)
            case _:
              IO.pure(Socket & U32, (s1, coll.score(h1, h3)))
        case H2.H2GotOk{+frame, +buf2}:
          match frame:
            case H2.H2Frame{+typ2, +flags2, +sid22, +payload2}:
              coll(2, (s1, H2.H2GotOk{frame, buf2}), h1, h3, d1, d3, fin, buf2, coll.setact(typ2, flags2), flags2, sid22, payload2, H2.H2Head{0, Nil{}}, False{}, 0)
    case 2:
      (s2, g2) = got
      match typ:
        case 1:
          do IO<Socket & U32>:
            got2 : Socket & H2.H2Got <- coll.ack(got)
            coll(0, got2, h1, h3, d1, d3, fin, buf, 0, 0, 0, Nil{}, H2.H2Head{0, Nil{}}, False{}, 0)
        case 2:
          coll(4, got, h1, h3, d1, d3, fin, buf, typ, flags, sid2, payload, coll.head_of(H2.h2_head.decode(payload)), coll.hd_ok(H2.h2_head.decode(payload)), U32.and(flags, H2.h2_f_end_stream()))
        case _:
          do IO<Socket & U32>:
            got2 : Socket & H2.H2Got <- H2.h2_read_frame(s2, buf)
            coll(0, got2, h1, h3, d1, d3, fin, buf, 0, 0, 0, Nil{}, H2.H2Head{0, Nil{}}, False{}, 0)
    case 4:
      coll(5, got, coll.slotH(okH, h, h1, U32.is_eq(sid2, 1)), coll.slotH(okH, h, h3, U32.is_eq(sid2, 3)), coll.slotD(okH, d1, e01, U32.is_eq(sid2, 1)), coll.slotD(okH, d3, e01, U32.is_eq(sid2, 3)), coll.done2(coll.slotD(okH, d1, e01, U32.is_eq(sid2, 1)), coll.slotD(okH, d3, e01, U32.is_eq(sid2, 3))), buf, 0, 0, 0, Nil{}, H2.H2Head{0, Nil{}}, False{}, 0)
    case 5:
      (s5, g5) = got
      match fin:
        case True{}:
          IO.pure(Socket & U32, coll.done_got(got, h1, h3))
        case False{}:
          do IO<Socket & U32>:
            got2 : Socket & H2.H2Got <- H2.h2_read_frame(s5, buf)
            coll(0, got2, h1, h3, d1, d3, fin, buf, 0, 0, 0, Nil{}, H2.H2Head{0, Nil{}}, False{}, 0)
    case _:
      IO.pure(Socket & U32, coll.done_got(got, h1, h3))

def client.collect.done(done: Socket & U32) -> IO(U32):
  (s2, score) = done
  do IO<U32>:
    x : Unit <- TLS.tls_close(s2)
    return score

def client.collect(sock: Socket) -> IO(U32):
  do IO<U32>:
    got : Socket & H2.H2Got <- H2.h2_read_frame(sock, Nil{})
    done : Socket & U32 <- coll(0, got, None{}, None{}, False{}, False{}, False{}, Nil{}, 0, 0, 0, Nil{}, H2.H2Head{0, Nil{}}, False{}, 0)
    client.collect.done(done)

# Raw pipelined sends: HEADERS(1) HEADERS(3) DATA(1,END) DATA(3,END).

def client.send4(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  (s4, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s4)
        IO.pure(U32, 0)
    case Done{u}:
      client.collect(s4)

def client.send3(sent: Socket & Result<&1, &1, U32 & String, Unit>, +d3: List<&2, U32>) -> IO(U32):
  (s3, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s3)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        sent4 : Socket & Result<&1, &1, U32 & String, Unit> <- H2.h2_send_frame(s3, H2.h2_t_data(), H2.h2_f_end_stream(), 3, d3)
        client.send4(sent4)

def client.send2(sent: Socket & Result<&1, &1, U32 & String, Unit>, +d1: List<&2, U32>, +d3: List<&2, U32>) -> IO(U32):
  (s2, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s2)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        sent3 : Socket & Result<&1, &1, U32 & String, Unit> <- H2.h2_send_frame(s2, H2.h2_t_data(), H2.h2_f_end_stream(), 1, d1)
        client.send3(sent3, d3)

def client.send1(sent: Socket & Result<&1, &1, U32 & String, Unit>, +h3: List<&2, U32>, +d1: List<&2, U32>, +d3: List<&2, U32>) -> IO(U32):
  (s1, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s1)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        sent2 : Socket & Result<&1, &1, U32 & String, Unit> <- H2.h2_send_frame(s1, H2.h2_t_headers(), H2.h2_f_end_headers(), 3, h3)
        client.send2(sent2, d1, d3)

def client.fire(sock: Socket) -> IO(U32):
  do IO<U32>:
    sent1 : Socket & Result<&1, &1, U32 & String, Unit> <- H2.h2_send_frame(sock, H2.h2_t_headers(), H2.h2_f_end_headers(), 1, H2.h2_request.head("POST", "/echo", Nil{}))
    client.send1(sent1, H2.h2_request.head("POST", "/echo", Nil{}), body1(), body2())

def client_conn(conn: Result<&1, &1, (U32 & String), Socket>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{sock}:
      client.fire(sock)

law client:
  for port: U32
  IO(U32)

def client(port):
  do IO<U32>:
    conn : Result<&1, &1, (U32 & String), Socket> <- H2.h2_connect_insecure("127.0.0.1", port)
    client_conn(conn)

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTPS.server_on_concurrent(~mux_ok, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    return "up"

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
    +total : U32 = (a : U32)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

law main:
  IO(U32)

def main():
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, 18440)
    main_go(b)

#|1
