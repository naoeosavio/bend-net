# io (httpx_h2_stream_cap): the server announces and enforces a cap of
# open streams (task-062 phase 1).
#
# Three claims, score 3:
#   * the initial SETTINGS carry MAX_CONCURRENT_STREAMS (id 3) = 100, byte
#     for byte;
#   * the peer opens 100 streams (HEADERS, END_HEADERS, no END_STREAM) and
#     the 101st is refused with RST_STREAM 7 (REFUSED_STREAM), so the
#     server never holds more than the cap;
#   * the connection lives: DATA(END_STREAM) on stream 1 after the refusal
#     gets a 200 HEADERS back.
# Before the fix SETTINGS carried no cap and the concurrent lane admitted
# every stream the peer sent.
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/tls.bend as TLS
import ../../lib/httpx.bend as HTTPX
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18547

def HOST() -> String:
  "127.0.0.1"

def CERT() -> String:
  "tests/io/tls_test_cert.pem"

def KEY() -> String:
  "tests/io/tls_test_key.pem"

# The cap of x_max_streams: 100 streams open at once.
def CAP() -> Nat:
  100n

# The sid of the first stream the cap refuses: 1, 3, 5 ... 201.
def REFUSED_SID() -> U32:
  201

# REFUSED_STREAM, the RST_STREAM code of the refusal.
def REFUSED() -> U32:
  7

# Acc bits: the refusal seen, the response seen.
def ACC_RST() -> U32:
  1

def ACC_RESP() -> U32:
  2

# Frames the peer reads before it gives up: SETTINGS, the refusal and the
# response, with room for the server's SETTINGS ACK.
def FUEL() -> Nat:
  16n

def b2u(b: Bool) -> U32:
  match b:
    case True{}:
      1
    case False{}:
      0

# The initial SETTINGS as bytes, in ascending id order: ENABLE_PUSH 0,
# MAX_CONCURRENT_STREAMS 100, INITIAL_WINDOW_SIZE 65535, MAX_FRAME_SIZE
# 65535.
def settings_bytes() -> List<&2, U32>:
  [0, 2, 0, 0, 0, 0, 0, 3, 0, 0, 0, 100, 0, 4, 0, 0, 255, 255, 0, 5, 0, 0, 255, 255]

def settings_ok() -> U32:
  b2u(U32.is_eq(HTTP.x_eq(HTTP2.x_settings_initial_pay(), settings_bytes()), 1))

# Opens fuel streams, two sids apart, and parks each one: HEADERS with
# END_HEADERS and no END_STREAM waits for the body of the request.
def head_send(fuel: Nat, m: Socket & Result<&1, &1, U32 & String, Unit>, +sid: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  match fuel:
    case 0n:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, m)
    case 1n+p:
      (s, r) = m
      match r:
        case Fail{e}:
          IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s, Fail{e}))
        case Done{u}:
          do IO<Socket & Result<&1, &1, U32 & String, Unit>>:
            sent : Socket & Result<&1, &1, U32 & String, Unit> <-
              HTTP2.x_send_frame(s, HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), sid,
                HTTP2.client.on.req_block(HOST(), PORT(), "GET", "/cap", Nil{}))
            head_send(p, sent, (sid + 2 : U32))

# Scenario step 2: the 101st HEADERS.
def head_cap(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s, Fail{e}))
    case Done{u}:
      HTTP2.x_send_frame(s, HTTP2.x_t_headers(), HTTP2.x_f_end_headers(), REFUSED_SID(),
        HTTP2.client.on.req_block(HOST(), PORT(), "GET", "/cap", Nil{}))

# Scenario step 3: the body of stream 1, so the server answers it.
def head_alive(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  (s, r) = m
  match r:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, U32 & String, Unit>, (s, Fail{e}))
    case Done{u}:
      HTTP2.x_send_frame(s, HTTP2.x_t_data(), HTTP2.x_f_end_stream(), 1, Nil{})

# A send becomes the seed of the read loop: a failed write keeps the code.
def sent_seed(m: Socket & Result<&1, &1, U32 & String, Unit>) -> Socket & HTTP.Got:
  (s, r) = m
  match r:
    case Fail{(code, msg)}:
      (s, HTTP.GotErr{code, msg})
    case Done{u}:
      (s, HTTP.GotErr{0, "next"})

# The phase after a frame: 2 stops, 0 reads on.
def next_phase(is_done: Bool) -> U32:
  match is_done:
    case True{}:
      2
    case False{}:
      0

def acc_full() -> U32:
  (ACC_RST() + ACC_RESP() : U32)

# Both bits set: the refusal and the answer were seen.
def is_full(+acc: U32) -> Bool:
  U32.is_eq(U32.and(acc, acc_full()), acc_full())

# One point per bit: the refusal and the answer, whatever repeats them.
def score_of(+acc: U32) -> U32:
  U32.add(b2u(U32.is_eq(U32.and(acc, ACC_RST()), ACC_RST())), b2u(U32.is_eq(U32.and(acc, ACC_RESP()), ACC_RESP())))

# The refusal of REFUSED_SID with REFUSED_STREAM: one acc bit.
def rst_ok(+typ: U32, +sid: U32, +payload: List<&2, U32>) -> U32:
  U32.mul(b2u(U32.is_eq(typ, HTTP2.x_t_rst())), U32.mul(b2u(U32.is_eq(sid, REFUSED_SID())), b2u(U32.is_eq(HTTP2.x_rst.code(payload), REFUSED()))))

# A HEADERS block with :status 200: one acc bit.
def resp_ok(dec: Result<&1, &1, U32 & String, HTTP.Head & HTTP.Tab>) -> U32:
  match dec:
    case Fail{e}:
      0
    case Done{value}:
      match value:
        case (head, tab):
          match head:
            case HTTP.Head{+status, +headers}:
              b2u(U32.is_eq(status, 200))

# One frame into the acc: the RST of the refused stream or the 200 answer.
def acc_add(+acc: U32, +typ: U32, +sid: U32, +payload: List<&2, U32>) -> U32:
  match typ:
    case 3:
      (acc + rst_ok(typ, sid, payload) : U32)
    case 1:
      (acc + resp_ok(HTTP2.x_resp.decode(payload, HTTP2.x_tab.empty())) : U32)
    case _:
      acc

def stop_at(got: Socket & HTTP.Got, +acc: U32) -> Socket & U32:
  (s, g) = got
  (s, acc)

def peer_read(fuel: Nat, ph: U32, got: Socket & HTTP.Got, +buf: List<&2, U32>, +acc: U32) ->
  IO(Socket & U32):
  match fuel:
    case 0n:
      IO.pure(Socket & U32, stop_at(got, acc))
    case 1n+p:
      match ph:
        case 0:
          (s0, g0) = got
          do IO<Socket & U32>:
            got2 : Socket & HTTP.Got <- HTTP2.x_read_frame(s0, buf)
            peer_read(p, 1, got2, buf, acc)
        case 1:
          (s1, g1) = got
          match g1:
            case HTTP.GotErr{code, msg}:
              IO.pure(Socket & U32, stop_at(got, acc))
            case HTTP.GotOk{+frame, +buf2}:
              match frame:
                case HTTP.Frame{+typ, +flags, +sid, +payload}:
                  +acc2 : U32 = U32.or(acc, acc_add(acc, typ, sid, payload))
                  peer_read(p, next_phase(is_full(acc2)), (s1, HTTP.GotOk{frame, buf2}), buf2, acc2)
        case _:
          (s9, g9) = got
          IO.pure(Socket & U32, stop_at(got, acc))

def peer_done(m: Socket & U32, +settings: U32) -> IO(U32):
  (s, +acc) = m
  do IO<U32>:
    x : Unit <- TLS.tls_close(s)
    return U32.add(settings, score_of(acc))

def peer_go(m: Socket & Result<&1, &1, U32 & String, Unit>, +settings: U32) -> IO(U32):
  (s, r) = m
  match r:
    case Fail{e}:
      peer_done((s, 0), settings)
    case Done{u}:
      do IO<U32>:
        got : Socket & HTTP.Got <- HTTP2.x_read_frame(s, Nil{})
        res : Socket & U32 <- peer_read(FUEL(), 1, got, Nil{}, 0)
        peer_done(res, settings)

def peer_start(sock: Socket) -> IO(U32):
  do IO<U32>:
    +settings : U32 = settings_ok()
    opened : Socket & Result<&1, &1, U32 & String, Unit> <-
      head_send(CAP(), (sock, Done{Unit{}}), 1)
    capped : Socket & Result<&1, &1, U32 & String, Unit> <- head_cap(opened)
    alive : Socket & Result<&1, &1, U32 & String, Unit> <- head_alive(capped)
    peer_go(alive, settings)

def peer_conn(conn: Result<&1, &1, U32 & String, Socket & HTTP.CliSt>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, st) = value
      peer_start(sock)

def peer(+port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, U32 & String, Socket & HTTP.CliSt> <- HTTPX.client.connect_insecure(HOST(), port)
    peer_conn(conn)

# The real buffered concurrent lane.
def echo(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, body})

def server(l: Listener) -> IO(String):
  do IO<String>:
    x : Unit <- HTTPX.server.concurrent(~echo, l, CERT(), KEY())
    return "up"

def listen_retry(port: U32, r: Result<&1, &1, (U32 & String), Listener>, rest: IO(Listener & U32)) -> IO(Listener & U32):
  match r:
    case Done{l}:
      IO.pure(Listener & U32, (l, port))
    case Fail{e}:
      rest

def listen_any(tries: Nat, +port: U32) -> IO(Listener & U32):
  match tries:
    case 0n:
      IO.die(Listener & U32, 1, "no free tcp port")
    case 1n+t:
      rest = listen_any(t, (port + 1 : U32))
      do IO<Listener & U32>:
        r : Result<&1, &1, (U32 & String), Listener> <- TCP.listen(port)
        listen_retry(port, r, rest)

def run(b: Listener & U32) -> IO(U32):
  (l, +port) = b
  do IO<U32>:
    chan : Chan(String) <- IO.fork(String, server(l))
    +score : U32 <- peer(port)
    return score

def main() -> IO(U32):
  do IO<U32>:
    b : Listener & U32 <- listen_any(32n, PORT())
    +total : U32 <- run(b)
    w : Unit <- IO.print(U32.show(total))
    z : Unit <- IO.die(Unit, 0, "")
    return total

#|3
