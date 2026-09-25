import Base
import ../../lib/http.bend as HTTP
import ../../lib/https_http1.bend as HTTP1
import ../../lib/tls.bend as TLS

def h1_echo(method: String, path: String,
  headers: List<&2, HTTP.Hdr>, body: String) ->
  IO(U32 & List<&1, String & String> & String):
  IO.pure(U32 & List<&1, String & String> & String,
    (200, [("X-HTTP1", "yes")], body))

def dual_conn.go(is_http1: Bool, sock: Socket, listener: Listener) ->
  IO(Listener):
  match is_http1:
    case True{}:
      HTTP1.http1_spawn(~h1_echo, sock, listener)
    case False{}:
      do IO<Listener>:
        closed : Unit <- TLS.tls_close(sock)
        return listener

def dual_conn(
  accepted: Listener & Result<&1, &1, (U32 & String), Socket & String>) ->
  IO(Listener):
  (listener, result) = accepted
  match result:
    case Fail{e}:
      IO.pure(Listener, listener)
    case Done{value}:
      (sock, protocol) = value
      is_http1 = TLS.tls_alpn_is_http1(protocol)
      dual_conn.go(is_http1, sock, listener)

@unsafe
def dual_server(listener: Listener) -> IO(Unit):
  do IO<Unit>:
    accepted : Listener & Result<&1, &1, (U32 & String), Socket & String> <-
      TLS.tls_accept_alpn(listener, "tests/io/tls_test_cert.pem",
        "tests/io/tls_test_key.pem")
    next : Listener <- dual_conn(accepted)
    dual_server(next)

def b2u(value: Bool) -> U32:
  match value:
    case True{}:
      1
    case False{}:
      0

def bytes_eq(left: List<&2, U32>, right: List<&2, U32>) -> U32:
  match left right:
    case Nil{} Nil{}:
      1
    case a <> aa b <> bb:
      (b2u(U32.is_eq(a, b)) * bytes_eq(aa, bb) : U32)
    case _ _:
      0

def client_result(
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
              * bytes_eq(body, HTTP.encode("hello")) : U32)

def client.conn(+port: U32,
  conn: Result<&1, &1, (U32 & String), Socket & String>) -> IO(U32):
  match conn:
    case Fail{e}:
      IO.pure(U32, 0)
    case Done{value}:
      (sock, protocol) = value
      is_http1 = TLS.tls_alpn_is_http1(protocol)
      do IO<U32>:
        got : Socket & Result<&1, &1, (U32 & String), HTTP1.HTTP1Response> <-
            HTTP1.http1_exch(sock, HTTP1.HTTPSCall{"127.0.0.1", port,
              "POST", "/dual", Nil{}, HTTP.encode("hello")})

        score : U32 <- client_result(got)
        return (b2u(is_http1) * score : U32)

def client(+port: U32) -> IO(U32):
  do IO<U32>:
    conn : Result<&1, &1, (U32 & String), Socket & String> <-
      TLS.tls_connect_raw("127.0.0.1", "127.0.0.1", port, 0, 3)
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
        result : Result<&1, &1, (U32 & String), Listener> <-
          TCP.listen(port)
        listen_retry(port, result, rest)

def main_go(bound: Listener & U32) -> IO(U32):
  (listener, port) = bound
  do IO<U32>:
    server : Chan(Unit) <- IO.fork(Unit, dual_server(listener))
    +score : U32 <- client(port)
    output : Unit <- IO.print(U32.show(score))
    stop : Unit <- IO.die(Unit, 0, "")
    return score

def main() -> IO(U32):
  do IO<U32>:
    bound : Listener & U32 <- listen_any(32n, 18750)
    main_go(bound)

#|1
