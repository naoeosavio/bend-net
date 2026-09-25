import Base
import ../../lib/http.bend as HTTP
import ../../lib/https_http1.bend as HTTP1
import ../../lib/tls.bend as TLS

def b2u(value: Bool) -> U32:
  match value:
    case True{}:
      1
    case False{}:
      0

def h1_echo(method: String, path: String,
  headers: List<&2, HTTP.Hdr>, body: String) ->
  IO(U32 & List<&1, String & String> & String):
  IO.pure(U32 & List<&1, String & String> & String,
    (200, [("X-HTTP1", "yes")], path ++ ":" ++ body))

def server_side(listener: Listener) -> IO(String):
  do IO<String>:
    result : Unit <- HTTP1.server_on_http1(~h1_echo, listener,
      "tests/io/tls_test_cert.pem", "tests/io/tls_test_key.pem")
    return "up"

def bytes_eq(left: List<&2, U32>, right: List<&2, U32>) -> U32:
  match left right:
    case Nil{} Nil{}:
      1
    case a <> aa b <> bb:
      (b2u(U32.is_eq(a, b)) * bytes_eq(aa, bb) : U32)
    case _ _:
      0

def chunked_result(
  result: Result<&1, &1, (U32 & String), HTTP1.HTTP1Response>) -> U32:
  match result:
    case Fail{e}:
      0
    case Done{response}:
      match response:
        case HTTP1.HTTP1Response{status, headers, body}:
          (b2u(U32.is_eq(status, 200))
            * bytes_eq(body, HTTP.encode("hello")) : U32)

def chunked_score() -> U32:
  response : Result<&1, &1, (U32 & String), HTTP1.HTTP1Response> =
    HTTP1.http1_response("GET", HTTP.encode(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"))
  chunked_result(response)

def binary_result(
  result: Result<&1, &1, (U32 & String), HTTP1.HTTP1Response>) -> U32:
  match result:
    case Fail{e}:
      0
    case Done{response}:
      match response:
        case HTTP1.HTTP1Response{status, headers, body}:
          (b2u(U32.is_eq(status, 200))
            * bytes_eq(body, [255, 0]) : U32)

def binary_score() -> U32:
  response : Result<&1, &1, (U32 & String), HTTP1.HTTP1Response> =
    HTTP1.http1_response("GET", List.append(&2, U32,
      HTTP.encode("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"),
      [255, 0]))
  binary_result(response)

def close_result(
  got: Socket & Result<&1, &1, (U32 & String), HTTP1.HTTP1Response>) -> IO(U32):
  (sock, result) = got
  match result:
    case Fail{e}:
      do IO<U32>:
        closed : Unit <- TLS.tls_close(sock)
        return 0
    case Done{response}:
      match response:
        case HTTP1.HTTP1Response{status, headers, body}:
          do IO<U32>:
            closed : Unit <- TLS.tls_close(sock)
            return (b2u(U32.is_eq(status, 200))
              * bytes_eq(body, HTTP.encode("/echo:hello")) : U32)

def fail_code(
  result: Result<&1, &1, (U32 & String), Socket & String>, code: U32) -> U32:
  match result:
    case Fail{(actual, message)}:
      b2u(U32.is_eq(actual, code))
    case Done{value}:
      0

def client.conn(+port: U32,
  conn: Result<&1, &1, (U32 & String), Socket & String>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, protocol) = value
      do IO<U32>:
        got : Socket & Result<&1, &1, (U32 & String), HTTP1.HTTP1Response> <-
          HTTP1.http1_exch(sock, HTTP1.HTTPSCall{"127.0.0.1", port,
            "POST", "/echo", [HTTP.Hdr{"X-Test", "yes"}],
            HTTP.encode("hello")})
        +score : U32 <- close_result(got)
        verify : Result<&1, &1, (U32 & String), Socket & String> <-
          TLS.tls_connect_any("127.0.0.1", port)
        return (b2u(TLS.tls_alpn_is_http1(protocol)) * score
          * fail_code(verify, 614) : U32)

def client(+port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, (U32 & String), Socket & String> <-
      TLS.tls_connect_any_insecure("127.0.0.1", port)
    client.conn(port, conn)

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
        result : Result<&1, &1, (U32 & String), Listener> <- TCP.listen(port)
        listen_retry(port, result, rest)

def main_go(bound: Listener & U32) -> IO(U32):
  (listener, port) = bound
  do IO<U32>:
    server : Chan(String) <- IO.fork(String, server_side(listener))
    +score : U32 <- client(port)
    +total : U32 = (score * chunked_score() * binary_score() : U32)
    output : Unit <- IO.print(U32.show(total))
    stop : Unit <- IO.die(Unit, 0, "")
    return total

def main() -> IO(U32):
  do IO<U32>:
    bound : Listener & U32 <- listen_any(32n, 18740)
    main_go(bound)

#|1
