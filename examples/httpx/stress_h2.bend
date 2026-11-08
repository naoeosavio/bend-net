# H2 load server for the stress matrix (task-063). Manual only, never in
# the gate: it binds 127.0.0.1:18960 and serves until Ctrl-C.
#   bend examples/httpx/stress_h2.bend <mode> [mb]
# Modes: echo (echo the body), drop (read the body, answer empty),
#        big (answer [mb] MiB), early (answer at the first DATA chunk),
#        drain (read the whole body as events, answer at the end),
#        ok (answer a 2-byte body, the h2spec mode).
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/http2.bend as HTTP2
import ../../lib/http.bend as HTTP

def PORT() -> U32:
  18960

def u32_go(m: Maybe<&2, U32>, +dflt: U32) -> U32:
  match m:
    case None{}:
      dflt
    case Some{v}:
      v

def rest_n(xs: List<String>) -> U32:
  match xs:
    case +h <> t:
      u32_go(U32.read(h), 1)
    case Nil{}:
      1

def arg_n(xs: List<String>) -> U32:
  match xs:
    case +m <> rest:
      rest_n(rest)
    case Nil{}:
      1

def args_of() -> IO(List<String>):
  IO.args()

@unsafe
def fill(n: U32, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0:
      acc
    case _:
      fill((n - 1 : U32), 97 <> acc)

def body_of(mb: U32) -> List<&2, U32>:
  fill((mb * 1048576 : U32), Nil{})

def echo_h(req: HTTP.Request) -> IO(HTTP.Response):
  match req:
    case HTTP.Request{+method, +path, +headers, +body}:
      IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, body})

def drop_h(req: HTTP.Request) -> IO(HTTP.Response):
  IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, Nil{}})

# The conformance answer: a 2-byte body, so every response carries a DATA
# frame and a peer sees the stream end. h2spec needs it (task-070 phase 1).
def ok_h(req: HTTP.Request) -> IO(HTTP.Response):
  IO.pure(HTTP.Response, HTTP.Response{200, Nil{}, [111, 107]})

def big_body(mb: U32) -> HTTP.Response:
  HTTP.Response{200, Nil{}, body_of(mb)}

def big_h(req: HTTP.Request) -> IO(HTTP.Response):
  do IO<HTTP.Response>:
    xs : List<String> <- args_of()
    IO.pure(HTTP.Response, big_body(arg_n(xs)))

# The stream form of a whole-body read: each chunk goes to the handler
# and is forgotten, and the final one answers 200. The server holds one
# chunk, not the body, so a 100 MB upload keeps a flat RSS.
def drain_h(ev: HTTP.SrvEv) -> HTTP.SrvOut:
  match ev:
    case HTTP.SrvReqHead{slot, head}:
      HTTP.Continue{}
    case HTTP.SrvReqData{slot, +chunk, fin}:
      match fin:
        case True{}:
          HTTP.RespondEarly{HTTP.Response{200, Nil{}, Nil{}}}
        case False{}:
          HTTP.Continue{}

def secho_h(ev: HTTP.SrvEv) -> HTTP.SrvOut:
  match ev:
    case HTTP.SrvReqHead{slot, head}:
      HTTP.Continue{}
    case HTTP.SrvReqData{slot, +chunk, fin}:
      HTTP.RespondEarly{HTTP.Response{200, Nil{}, chunk}}

def mk_go(eq: Bool, +code: U32, rec: U32) -> U32:
  match eq:
    case True{}:
      code
    case False{}:
      rec

def mk(+m: String, +want: String, +code: U32, rec: U32) -> U32:
  mk_go(String.eq(m, want), code, rec)

def mode_code(+m: String) -> U32:
  mk(m, "echo", 1,
    mk(m, "drop", 2,
      mk(m, "big", 3,
        mk(m, "early", 4,
          mk(m, "drain", 5,
            mk(m, "ok", 6, 0))))))

def run(code: U32, l: Listener) -> IO(Unit):
  match code:
    case 1:
      HTTP2.server.concurrent(~echo_h, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    case 2:
      HTTP2.server.concurrent(~drop_h, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    case 3:
      HTTP2.server.concurrent(~big_h, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    case 4:
      HTTP2.server.stream.concurrent(~secho_h, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    case 5:
      HTTP2.server.stream.concurrent(~drain_h, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    case 6:
      HTTP2.server.concurrent(~ok_h, l, "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    case _:
      IO.die(Unit, 2, "bad mode")

def after(code: U32, r: Result<&1, &1, U32 & String, Listener>) -> IO(Unit):
  match r:
    case Fail{e}:
      IO.die(Unit, 1, "listen")
    case Done{l}:
      do IO<Unit>:
        x : Unit <- IO.print("LISTEN")
        run(code, l)

def go(xs: List<String>) -> IO(Unit):
  match xs:
    case +m <> rest:
      do IO<Unit>:
        r : Result<&1, &1, U32 & String, Listener> <- TCP.listen_backlog(PORT(), TCP.LISTEN_BACKLOG())
        after(mode_code(m), r)
    case Nil{}:
      IO.die(Unit, 2, "no mode")

def main() -> IO(Unit):
  do IO<Unit>:
    xs : List<String> <- IO.args()
    go(xs)
