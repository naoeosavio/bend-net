# lib (lib_httpx_mux): truly interleaved streams on one HTTPS
# connection against HTTPX.server.concurrent's mux. The client
# pipelines HEADERS(1,3,5,7) then DATA(7,5,3,1,END) raw — four open
# streams at once, completed in reverse (crossed) order; the server
# must answer all four while all are open (a sequential server would
# corrupt state, a 2-slot mux would fail the connection closed). The
# handler answers 200 with an empty body, so responses are
# HEADERS(END_STREAM) only; the client counts the four 200 heads in
# any arrival order. Golden 1.
import Base
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def body1() -> List<&2, U32>:
  [104, 101, 108, 108, 111]

def body2() -> List<&2, U32>:
  [119, 111, 114, 108, 100, 33]

def mux_ok(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, Nil{}})

# Client collect: gather HEADERS for sids 1, 3, 5 and 7 (handler
# answers 200 with empty bodies, so no DATA is ever read). Score is 1
# iff all four decoded with :status 200. Responses may arrive in any
# order, so the collector counts 200/END_STREAM heads instead of
# slotting per sid. One @unsafe self-recursive def; each phase carries
# at most one single match; slot decisions ride leaf calls.

def coll.score_go(eq: Bool) -> U32:
  match eq:
    case True{}:
      1
    case False{}:
      0

def coll.score(+n: U32) -> U32:
  coll.score_go(U32.is_eq(n, 4))

# HTTP2.x_resp.decode returns Result<..., Head & Tab> where the legacy
# H2.h2_head.of(H2.h2_head.decode(...)) unwrapped it to Result<..., Head>.
# Keeping the Result in the signature and letting x_resp.ok / x_resp.rh do the
# unwrap is the same shape the old hd_ok / head_of had.
def coll.hd_ok(dec: Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab>) -> Bool:
  HTTP2.x_resp.ok(dec)

def coll.head_of(dec: Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab>) -> HTTP.Head:
  HTTP2.x_resp.rh(dec)

def coll.is200(+h: HTTP.Head) -> Bool:
  match h:
    case HTTP.Head{status, headers}:
      U32.is_eq(status, 200)

def coll.hit(ok: Bool, +h: HTTP.Head, +e: U32) -> Bool:
  match ok e:
    case True{} 1:
      coll.is200(h)
    case _ _:
      False{}

def coll.bump(hit: Bool, +n: U32) -> U32:
  match hit:
    case True{}:
      (n + 1 : U32)
    case False{}:
      n

def coll.fin4(+n: U32) -> Bool:
  U32.is_ge(n, 4)

def coll.acked(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & HTTP.Got:
  (s2, r) = sent
  match r:
    case Fail{e}:
      (s2, HTTP.GotErr{616, "tls io"})
    case Done{u}:
      (s2, HTTP.GotErr{0, "next"})

def coll.ack(got: Socket & HTTP.Got) -> IO(Socket & HTTP.Got):
  (s, g) = got
  do IO<Socket & HTTP.Got>:
    sent : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s, HTTP2.x_t_settings(), HTTP2.x_f_ack(), 0, Nil{})
    IO.pure(Socket & HTTP.Got, coll.acked(sent))

def coll.done_got(got: Socket & HTTP.Got, +n: U32) -> Socket & U32:
  (s, g) = got
  (s, coll.score(n))

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
def coll(phase: U32, got: Socket & HTTP.Got, +n: U32, fin: Bool, +buf: List<&2, U32>, typ: U32, +flags: U32, +sid2: U32, +payload: List<&2, U32>, +h: HTTP.Head, +okH: Bool, +e01: U32) ->
  IO(Socket & U32):
  match phase:
    case 0:
      match fin:
        case True{}:
          IO.pure(Socket & U32, coll.done_got(got, n))
        case False{}:
          coll(1, got, n, fin, buf, 0, 0, 0, Nil{}, HTTP.Head{0, Nil{}}, False{}, 0)
    case 1:
      (s1, g1) = got
      match g1:
        case HTTP.GotErr{code, msg}:
          match code:
            case 0:
              do IO<Socket & U32>:
                got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s1, buf)
                coll(1, got2, n, fin, buf, 0, 0, 0, Nil{}, HTTP.Head{0, Nil{}}, False{}, 0)
            case _:
              IO.pure(Socket & U32, (s1, coll.score(n)))
        case HTTP.GotOk{+frame, +buf2}:
          match frame:
            case HTTP.Frame{+typ2, +flags2, +sid22,+flen, +payload2}:
              coll(2, (s1, HTTP.GotOk{frame, buf2}), n, fin, buf2, coll.setact(typ2, flags2), flags2, sid22, payload2, HTTP.Head{0, Nil{}}, False{}, 0)
    case 2:
      (s2, g2) = got
      match typ:
        case 1:
          do IO<Socket & U32>:
            got2 : Socket & HTTP.Got <- coll.ack(got)
            coll(0, got2, n, fin, buf, 0, 0, 0, Nil{}, HTTP.Head{0, Nil{}}, False{}, 0)
        case 2:
          +dec : Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab> =
            HTTP2.x_resp.decode(payload, HTTP2.x_tab.empty())
          coll(4, got, n, fin, buf, typ, flags, sid2, payload,
            coll.head_of(dec), coll.hd_ok(dec),
            U32.and(flags, HTTP2.x_f_end_stream()))
        case _:
          do IO<Socket & U32>:
            got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s2, buf)
            coll(0, got2, n, fin, buf, 0, 0, 0, Nil{}, HTTP.Head{0, Nil{}}, False{}, 0)
    case 4:
      +n2 = coll.bump(coll.hit(okH, h, e01), n)
      coll(5, got, n2, coll.fin4(n2), buf, 0, 0, 0, Nil{}, HTTP.Head{0, Nil{}}, False{}, 0)
    case 5:
      (s5, g5) = got
      match fin:
        case True{}:
          IO.pure(Socket & U32, coll.done_got(got, n))
        case False{}:
          do IO<Socket & U32>:
            got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s5, buf)
            coll(0, got2, n, fin, buf, 0, 0, 0, Nil{}, HTTP.Head{0, Nil{}}, False{}, 0)
    case _:
      IO.pure(Socket & U32, coll.done_got(got, n))

def client.collect.done(done: Socket & U32) -> IO(U32):
  (s2, score) = done
  do IO<U32>:
    x : Unit <- TLS.tls_close(s2)
    return score

def client.collect(sock: Socket) -> IO(U32):
  do IO<U32>:
    got : Socket & HTTP.Got <- HTTP2.x_read_frame(sock, Nil{})
    done : Socket & U32 <- coll(0, got, 0, False{}, Nil{}, 0, 0, 0, Nil{}, HTTP.Head{0, Nil{}}, False{}, 0)
    client.collect.done(done)

# Raw pipelined sends: HEADERS(1) HEADERS(3) HEADERS(5) HEADERS(7)
# then DATA(7,END) DATA(5,END) DATA(3,END) DATA(1,END) — four open
# streams at once, completed in reverse (crossed) order.

def client.send8(sent: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(U32):
  (s4, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s4)
        IO.pure(U32, 0)
    case Done{u}:
      client.collect(s4)

def client.send7(sent: Socket & Result<&1, &1, U32 & String, Unit>, +d1: List<&2, U32>) -> IO(U32):
  (s3, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s3)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        sent8 : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s3, HTTP2.x_t_data(), HTTP2.x_f_end_stream(), 1, d1)
        client.send8(sent8)

def client.send6(sent: Socket & Result<&1, &1, U32 & String, Unit>, +d1: List<&2, U32>, +d3: List<&2, U32>) -> IO(U32):
  (s2, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s2)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        sent7 : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s2, HTTP2.x_t_data(), HTTP2.x_f_end_stream(), 3, d3)
        client.send7(sent7, d1)

def client.send5(sent: Socket & Result<&1, &1, U32 & String, Unit>, +d1: List<&2, U32>, +d3: List<&2, U32>, +d5: List<&2, U32>) -> IO(U32):
  (s5, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s5)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        sent6 : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s5, HTTP2.x_t_data(), HTTP2.x_f_end_stream(), 5, d5)
        client.send6(sent6, d1, d3)

def client.send4(sent: Socket & Result<&1, &1, U32 & String, Unit>, +d1: List<&2, U32>, +d3: List<&2, U32>, +d5: List<&2, U32>, +d7: List<&2, U32>) -> IO(U32):
  (s6, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s6)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        sent5 : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s6, HTTP2.x_t_data(), HTTP2.x_f_end_stream(), 7, d7)
        client.send5(sent5, d1, d3, d5)

def client.send3(sent: Socket & Result<&1, &1, U32 & String, Unit>, +h7: List<&2, U32>, +d1: List<&2, U32>, +d3: List<&2, U32>, +d5: List<&2, U32>, +d7: List<&2, U32>) -> IO(U32):
  (s7, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s7)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        sent4 : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s7, HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 7, h7)
        client.send4(sent4, d1, d3, d5, d7)

def client.send2(sent: Socket & Result<&1, &1, U32 & String, Unit>, +h5: List<&2, U32>, +h7: List<&2, U32>, +d1: List<&2, U32>, +d3: List<&2, U32>, +d5: List<&2, U32>, +d7: List<&2, U32>) -> IO(U32):
  (s8, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s8)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        sent3 : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s8, HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 5, h5)
        client.send3(sent3, h7, d1, d3, d5, d7)

def client.send1(sent: Socket & Result<&1, &1, U32 & String, Unit>, +h3: List<&2, U32>, +h5: List<&2, U32>, +h7: List<&2, U32>, +d1: List<&2, U32>, +d3: List<&2, U32>, +d5: List<&2, U32>, +d7: List<&2, U32>) -> IO(U32):
  (s1, r) = sent
  match r:
    case Fail{e}:
      do IO<U32>:
        x : Unit <- TLS.tls_close(s1)
        IO.pure(U32, 0)
    case Done{u}:
      do IO<U32>:
        sent2 : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(s1, HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 3, h3)
        client.send2(sent2, h5, h7, d1, d3, d5, d7)

def client.fire(sock: Socket, +port: U32) -> IO(U32):
  do IO<U32>:
    # The legacy H2.h2_request.head(method, path, hs) rendered :method, :path
    # and :scheme but no :authority. HTTP2.client.on.req_block is the same
    # renderer plus the :authority it derives from the host and port -- which
    # is why the port is threaded in here.
    h1 : List<&2, U32> = HTTP2.client.on.req_block("127.0.0.1", port, "POST", "/echo", Nil{})
    h3 : List<&2, U32> = HTTP2.client.on.req_block("127.0.0.1", port, "POST", "/echo", Nil{})
    h5 : List<&2, U32> = HTTP2.client.on.req_block("127.0.0.1", port, "POST", "/echo", Nil{})
    h7 : List<&2, U32> = HTTP2.client.on.req_block("127.0.0.1", port, "POST", "/echo", Nil{})
    sent1 : Socket & Result<&1, &1, U32 & String, Unit> <- HTTP2.x_send_frame(sock, HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), 1, h1)
    client.send1(sent1, h3, h5, h7, body1(), body2(), body1(), body2())

def client_conn(conn: Result<&1, &1, (U32 & String), Socket & HTTP.CliSt>, +port: U32) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, st) = value
      client.fire(sock, port)

law client:
  for +port: U32
  IO(U32)

def client(port):
  do IO<U32>:
    conn : Result<&1, &1, (U32 & String), Socket & HTTP.CliSt> <- HTTPX.client.connect_insecure("127.0.0.1", port)
    client_conn(conn, port)

law server_side:
  for l: Listener
  IO(String)

def server_side(l):
  do IO<String>:
    x : Unit <- HTTPX.server.concurrent(~mux_ok, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
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
