import Base
import ../lib/http.bend as HTTP
import ../lib/http2.bend as H2
import ../lib/https.bend as HTTPS

def h2_echo(request: H2.H2Request) -> IO(H2.H2Response):
  match request:
    case H2.H2Request{method, path, headers, body}:
      IO.pure(H2.H2Response, H2.H2Response{200, Nil{}, body})

def h1_echo(method: String, path: String,
  headers: List<&2, HTTP.Hdr>, body: String) ->
  IO(U32 & List<&1, String & String> & String):
  IO.pure(U32 & List<&1, String & String> & String,
    (200, [("Content-Type", "text/plain")], body))

def serve(listener: Listener) -> IO(Unit):
  do IO<Unit>:
    result : Unit <- HTTPS.server_on_alpn(~h2_echo, ~h1_echo, listener,
      "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    return result

def main_result(
  result: Result<&1, &1, (U32 & String), Listener>) -> IO(Unit):
  match result:
    case Fail{e}:
      IO.die(Unit, 1, "listen failed")
    case Done{listener}:
      do IO<Unit>:
        output : Unit <- IO.print("LISTEN 19895")
        serve(listener)

def main() -> IO(Unit):
  do IO<Unit>:
    result : Result<&1, &1, (U32 & String), Listener> <- TCP.listen(19895)
    main_result(result)
