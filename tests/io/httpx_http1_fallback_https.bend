# lib (lib_httpx_http1_fallback_https): H1 fallback of the dual client.
# The server offers http/1.1 only (HTTPX.server.on_h1, one unified handler);
# the client is HTTPX.request_insecure, which offers h2+http/1.1, negotiates
# http/1.1 and transparently takes the H1 lane. Also pins the H1 request
# renderer: :authority and connection are rewritten/dropped and the Host line
# is synthesised from the host and port.
import Base
import ../../lib/httpx.bend as HTTPX
import ../../lib/tls.bend as TLS

def b2u(value: Bool) -> U32:
  match value:
    case True{}:
      1
    case False{}:
      0

def pure_alpn_score() -> U32:
  (b2u(TLS.tls_alpn_is_h2("h2"))
  + b2u(TLS.tls_alpn_is_http1("http/1.1"))
  + b2u(Bool.not(TLS.tls_alpn_is_h2("")))
  + b2u(Bool.not(TLS.tls_alpn_is_http1("h2"))) : U32)

def request_text(
  result: Result<&1, &1, (U32 & String), List<&2, U32>>) -> String:
  match result:
    case Fail{e}:
      ""
    case Done{body}:
      HTTPX.x_bytes_str(body)

# The H1 wire text for a request whose header list still carries the H2-only
# pseudo-header: HTTPX.x_h1.render_req is the renderer (it drops :authority
# and synthesises Host), so the old HTTPS.h1_headers + HTTP1.http1_bytes pair
# collapses into one call. A Fail renders as "" and every assertion below goes
# to 0, so a rejected render cannot pass silently.
def pure_h1_headers() -> U32:
  headers : List<&2, HTTPX.Hdr> =
    HTTPX.Hdr{":authority", "127.0.0.1:18640"}
    <> HTTPX.Hdr{"connection", "keep-alive"}
    <> HTTPX.Hdr{"x-test", "yes"}
    <> Nil{}
  +text : String = request_text(
    HTTPX.x_h1.render_req("GET", "/probe", "127.0.0.1", 18640, headers, Nil{}))
  (b2u(String.contains(text, "Host: 127.0.0.1:18640"))
  * b2u(String.contains(text, "x-test: yes"))
  * b2u(Bool.not(String.contains(text, ":authority")))
  * b2u(Bool.not(String.contains(text, "keep-alive"))) : U32)

def httpx_echo(req: HTTPX.Request) -> IO(HTTPX.Response):
  match req:
    case HTTPX.Request{+method, +path, +headers, +body}:
      # path ":" body as bytes, so the client sees the same "/echo:hello" the
      # old String-shaped h1_echo produced. `++` is String concat here and
      # HTTPX.x_cat REVERSES a list (it un-reverses the reversed-accumulator
      # idiom), so byte lists join with nested List.append only.
      out : List<&2, U32> = List.append(&2, U32,
        List.append(&2, U32, HTTPX.x_str_bytes(path), HTTPX.x_str_bytes(":")),
        body)
      IO.pure(HTTPX.Response, HTTPX.Response{200, [HTTPX.Hdr{"X-HTTP1", "yes"}], out})

def server_side(listener: Listener) -> IO(String):
  do IO<String>:
    result : Unit <- HTTPX.server.on_h1(~httpx_echo, listener,
      "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    return "up"

def client_score(
  result: Result<&1, &1, (U32 & String), String>) -> U32:
  match result:
    case Fail{e}:
      0
    case Done{body}:
      b2u(String.eq(body, "/echo:hello"))

def fail_code(
  result: Result<&1, &1, (U32 & String), Socket>, code: U32) -> U32:
  match result:
    case Fail{(actual, message)}:
      b2u(U32.is_eq(actual, code))
    case Done{sock}:
      0

def roundtrip(+port: U32) -> IO(U32):
  do IO<U32>:
    result : Result<&1, &1, (U32 & String), String> <-
      HTTPX.request_insecure("127.0.0.1", port, "/echo", "POST",
        Nil{}, "hello")
    verify : Result<&1, &1, (U32 & String), Socket> <-
      TLS.tls_connect("127.0.0.1", port)
    return (client_score(result) * fail_code(verify, 614) : U32)

def listen_retry(port: U32,
  result: Result<&1, &1, (U32 & String), Listener>,
  rest: IO(Listener & U32)) -> IO(Listener & U32):
  match result:
    case Done{listener}:
      IO.pure(Listener & U32, (listener, port))
    case Fail{e}:
      rest

def listen_any(tries: Nat, +port: U32) -> IO(Listener & U32):
  match tries:
    case 0n:
      IO.die(Listener & U32, 1, "no free tcp port")
    case 1n+t:
      rest : IO(Listener & U32) = listen_any(t, (port + 1 : U32))
      do IO<Listener & U32>:
        result : Result<&1, &1, (U32 & String), Listener> <-
          TCP.listen(port)
        listen_retry(port, result, rest)

def main_go(bound: Listener & U32) -> IO(U32):
  (listener, port) = bound
  do IO<U32>:
    server : Chan(String) <- IO.fork(String, server_side(listener))
    +score : U32 <- roundtrip(port)
    +total : U32 = (pure_alpn_score() * pure_h1_headers() * score : U32)
    output : Unit <- IO.print(U32.show(total))
    stop : Unit <- IO.die(Unit, 0, "")
    return total

def main() -> IO(U32):
  do IO<U32>:
    bound : Listener & U32 <- listen_any(32n, 18640)
    main_go(bound)

#|4