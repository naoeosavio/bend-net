import Base
import ../../lib/http.bend as HTTP
import ../../lib/http2.bend as H2
import ../../lib/https.bend as HTTPS
import ../../lib/https_http1.bend as HTTP1
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
      H2.bytes_str(body)

def pure_h1_headers() -> U32:
  headers : List<&2, H2.H2Hdr> =
    H2.H2Hdr{":authority", "127.0.0.1:18640"}
    <> H2.H2Hdr{"connection", "keep-alive"}
    <> H2.H2Hdr{"x-test", "yes"}
    <> Nil{}
  filtered : List<&2, HTTP.Hdr> = HTTPS.h1_headers(headers)
  result : Result<&1, &1, (U32 & String), List<&2, U32>> =
    HTTP1.http1_bytes.authority("GET", "/probe", "127.0.0.1",
      18640, filtered, Nil{})
  +text : String = request_text(result)
  (b2u(String.contains(text, "Host: 127.0.0.1:18640"))
  * b2u(String.contains(text, "x-test: yes"))
  * b2u(Bool.not(String.contains(text, ":authority")))
  * b2u(Bool.not(String.contains(text, "keep-alive"))) : U32)

def h1_echo(method: String, path: String,
  headers: List<&2, HTTP.Hdr>, body: String) ->
  IO(U32 & List<&1, String & String> & String):
  IO.pure(U32 & List<&1, String & String> & String,
    (200, [("X-HTTP1", "yes")], path ++ ":" ++ body))

def server_side(listener: Listener) -> IO(String):
  do IO<String>:
    result : Unit <- HTTPS.server_on_http1(~h1_echo, listener,
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
      HTTPS.send_request_insecure("127.0.0.1", port, "/echo", "POST",
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

#|1
