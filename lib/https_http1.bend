import Base
import ./http.bend as HTTP
import ./tls.bend as TLS

type HTTP1Request is Data:
  HTTP1Request{method: String, path: String, headers: List<&2, HTTP.Hdr>, body: String}

type HTTP1Response is Data:
  HTTP1Response{status: U32, headers: List<&2, HTTP.Hdr>, body: List<&2, U32>}

type HTTPSCall is Data:
  HTTPSCall{host: String, port: U32, method: String, path: String, headers: List<&2, HTTP.Hdr>, body: List<&2, U32>}

type HTTP1ServeState is Data:
  HTTP1ServeState{request: HTTP1Request, bytes: List<&2, U32>, ready: Bool}

def http1_pairs(headers: List<&2, HTTP.Hdr>) ->
  List<&1, String & String>:
  match headers:
    case Nil{}:
      Nil{}
    case HTTP.Hdr{name, value} <> tail:
      (name, value) <> http1_pairs(tail)

def http1_forbidden(+name: String) -> Bool:
  Bool.or(String.starts_with(name, ":"),
    Bool.or(HTTP.eq_ci(name, "host"),
      Bool.or(HTTP.eq_ci(name, "connection"),
        Bool.or(HTTP.eq_ci(name, "content-length"),
          Bool.or(HTTP.eq_ci(name, "transfer-encoding"),
            Bool.or(HTTP.eq_ci(name, "upgrade"),
              HTTP.eq_ci(name, "keep-alive")))))))

def http1_bytes.of(
  result: Result<&1, &1, (U32 & String), String>) ->
  Result<&1, &1, (U32 & String), List<&2, U32>>:
  match result:
    case Fail{e}:
      Fail{e}
    case Done{text}:
      Done{HTTP.encode(text)}

def http1_bytes.authority(+method: String, +path: String,
  +host: String, +port: U32, hs: List<&2, HTTP.Hdr>,
  +body: List<&2, U32>) ->
  Result<&1, &1, (U32 & String), List<&2, U32>>:
  http1_bytes.of(HTTP.show_request(method, path,
    ("Host", host ++ ":" ++ U32.show(port)) <> http1_pairs(hs),
    HTTP.decode(body)))

def http1_body_bytes.put(cl: U32, raw: List<&2, U32>, short: Bool) ->
  Result<&1, &1, (U32 & String), List<&2, U32>>:
  match short:
    case True{}:
      Fail{(413, "body too large")}
    case False{}:
      Done{HTTP.bs_take(raw, U32.to_nat(cl))}

def http1_body_bytes.cl(+cl: U32, +raw: List<&2, U32>) ->
  Result<&1, &1, (U32 & String), List<&2, U32>>:
  http1_body_bytes.put(cl, raw,
    Bool.and(U32.is_gt(cl, 0), Bool.not(Nat.is_le(U32.to_nat(cl), HTTP.length_nat(raw)))))

type HTTP1Frame is Data:
  HTTP1Frame{cl: U32, chunked: Bool, no_body: Bool}

def http1_body_bytes.pick(cl: U32, chunked: Bool,
  raw: List<&2, U32>) ->
  Result<&1, &1, (U32 & String), List<&2, U32>>:
  match chunked:
    case True{}:
      HTTP.unchunk(raw)
    case False{}:
      http1_body_bytes.cl(cl, raw)

def http1_body_bytes.go(frame: HTTP1Frame,
  raw: List<&2, U32>) ->
  Result<&1, &1, (U32 & String), List<&2, U32>>:
  match frame:
    case HTTP1Frame{cl, chunked, no_body}:
      match no_body:
        case True{}:
          Done{Nil{}}
        case False{}:
          http1_body_bytes.pick(cl, chunked, raw)

def http1_body_bytes.frame.go(fr: U32 & Bool, method: String, status: U32) ->
  HTTP1Frame:
  (cl, chunked) = fr
  HTTP1Frame{cl, chunked, HTTP.fetch.body.no_body(method, status)}

def http1_body_bytes.frame(
  headers: List<&2, HTTP.Hdr>, method: String, status: U32) -> HTTP1Frame:
  http1_body_bytes.frame.go(
    HTTP.fetch.body.frame.go(http1_pairs(headers), 0, False{}),
    method, status)

def http1_response_bytes.finish(status: U32,
  headers: List<&2, HTTP.Hdr>,
  body: Result<&1, &1, (U32 & String), List<&2, U32>>) ->
  Result<&1, &1, (U32 & String), HTTP1Response>:
  match body:
    case Fail{e}:
      Fail{e}
    case Done{bytes}:
      Done{HTTP1Response{status, headers, bytes}}

def http1_response_bytes(
  head: Result<&1, &1, (U32 & String), (U32 & List<&1, String & String> & String)>,
  method: String, acc: List<&2, U32>) ->
  Result<&1, &1, (U32 & String), HTTP1Response>:
  match head:
    case Fail{e}:
      Fail{e}
    case Done{value}:
      (status, headers, _) = value
      +st = status
      +hd = HTTP.to_hdrs(headers)
      +frame_headers = hd
      frame = http1_body_bytes.frame(frame_headers, method, st)
      body = http1_body_bytes.go(frame, HTTP.bs_body(acc))
      http1_response_bytes.finish(st, hd, body)

def http1_response(+method: String,
  +acc: List<&2, U32>) ->
  Result<&1, &1, (U32 & String), HTTP1Response>:
  http1_response_bytes(
    HTTP.read_response(HTTP.decode(HTTP.bs_head(acc))), method, acc)

def http1_next_fuel(fuel: Nat) -> Nat:
  match fuel:
    case 0n:
      0n
    case 1n+rest:
      rest

@unsafe
def http1_recv(phase: U32,
  got: Socket & Result<&1, &1, (U32 & String), List<&2, U32>>,
  +method: String, +acc: List<&2, U32>,
  parsed: Result<&1, &1, (U32 & String), HTTP1Response>, fuel: Nat) ->
  IO(Socket & Result<&1, &1, (U32 & String), HTTP1Response>):
  match phase:
    case 0:
      (sock, result) = got
      match fuel:
        case 0n:
          IO.pure(Socket & Result<&1, &1, (U32 & String), HTTP1Response>,
            (sock, Fail{(413, "response too long")}))
        case 1n+rest:
          do IO<Socket & Result<&1, &1, (U32 & String), HTTP1Response>>:
            next : Socket & Result<&1, &1, (U32 & String), List<&2, U32>> <-
              TLS.tls_recv_bytes(sock, 16384)
            http1_recv(1, next, method, acc, parsed, rest)
    case 1:
      (sock, result) = got
      match result:
        case Fail{e}:
          IO.pure(Socket & Result<&1, &1, (U32 & String), HTTP1Response>,
            (sock, Fail{e}))
        case Done{part}:
          match part:
            case Nil{}:
              IO.pure(Socket & Result<&1, &1, (U32 & String), HTTP1Response>,
                (sock, Fail{(400, "eof")}))
            case h <> t:
              +next = List.append(&2, U32, acc, part)
              http1_recv(2, (sock, Done{Nil{}}), method, next,
                http1_response(method, next), fuel)
    case 2:
      (sock, result) = got
      match parsed:
        case Done{response}:
          IO.pure(Socket & Result<&1, &1, (U32 & String), HTTP1Response>,
            (sock, Done{response}))
        case Fail{e}:
          do IO<Socket & Result<&1, &1, (U32 & String), HTTP1Response>>:
            next : Socket & Result<&1, &1, (U32 & String), List<&2, U32>> <-
              TLS.tls_recv_bytes(sock, 16384)
            http1_recv(1, next, method, acc, parsed,
              http1_next_fuel(fuel))
    case _:
      (sock, result) = got
      IO.pure(Socket & Result<&1, &1, (U32 & String), HTTP1Response>,
        (sock, Fail{(616, "tls io")}))

def http1_sent(sent: Socket & Result<&1, &1, (U32 & String), Unit>,
  +method: String) -> IO(Socket & Result<&1, &1, (U32 & String), HTTP1Response>):
  (sock, result) = sent
  match result:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, (U32 & String), HTTP1Response>,
        (sock, Fail{e}))
    case Done{unit}:
      http1_recv(0, (sock, Done{Nil{}}), method, Nil{},
        Fail{(400, "response not started")}, 64n)

def http1_sent.go(bytes: Result<&1, &1, (U32 & String), List<&2, U32>>,
  sock: Socket, +method: String) ->
  IO(Socket & Result<&1, &1, (U32 & String), HTTP1Response>):
  match bytes:
    case Fail{e}:
      IO.pure(Socket & Result<&1, &1, (U32 & String), HTTP1Response>,
        (sock, Fail{e}))
    case Done{data}:
      do IO<Socket & Result<&1, &1, (U32 & String), HTTP1Response>>:
        sent : Socket & Result<&1, &1, (U32 & String), Unit> <-
          TLS.tls_send_bytes(sock, data)
        http1_sent(sent, method)

def http1_exch(sock: Socket, call: HTTPSCall) ->
  IO(Socket & Result<&1, &1, (U32 & String), HTTP1Response>):
  match call:
    case HTTPSCall{host, port, +method, path, headers, body}:
      http1_sent.go(http1_bytes.authority(method, path,
        host, port, headers, body), sock, method)

def http1_apply.response(
  response: U32 & List<&1, String & String> & String) -> HTTP1Response:
  (status, headers, body) = response
  HTTP1Response{status, HTTP.to_hdrs(headers), HTTP.encode(body)}

def http1_apply(
  ~H: String -> String -> List<&2, HTTP.Hdr> -> String -> IO(U32 & List<&1, String & String> & String),
  request: HTTP1Request) -> IO(HTTP1Response):
  match request:
    case HTTP1Request{method, path, headers, body}:
      do IO<HTTP1Response>:
        response : U32 & List<&1, String & String> & String <-
          H(method, path, headers, body)
        return http1_apply.response(response)

def http1_show(response: HTTP1Response) ->
  Result<&1, &1, (U32 & String), String>:
  match response:
    case HTTP1Response{status, headers, body}:
      HTTP.show_response(status, HTTP.drop_conn(http1_pairs(headers)),
        HTTP.decode(body))

def http1_request.of(
  value: Bool & (String & String & List<&1, String & String> & String)) ->
  Result<&1, &1, (U32 & String), HTTP1Request>:
  (is_http11, request) = value
  (method, path, headers, body) = request
  Done{HTTP1Request{method, path, HTTP.to_hdrs(headers), body}}

def http1_request.read(
  result: Result<&1, &1, (U32 & String), Bool & (String & String & List<&1, String & String> & String)>) ->
  Result<&1, &1, (U32 & String), HTTP1Request>:
  match result:
    case Fail{e}:
      Fail{e}
    case Done{request}:
      http1_request.of(request)

def http1_request.parse(bytes: List<&2, U32>) ->
  Result<&1, &1, (U32 & String), HTTP1Request>:
  http1_request.read(HTTP.read_head(HTTP.decode(HTTP.bs_head(bytes))))

def http1_serve.ready(headers: List<&2, HTTP.Hdr>, body: String) -> Bool:
  Nat.is_le(U32.to_nat(HTTP.cl_of(headers)), String.length(body))

def http1_serve.close_sent(
  sent: Socket & Result<&1, &1, (U32 & String), Unit>) -> IO(Unit):
  (sock, result) = sent
  TLS.tls_close(sock)

def http1_serve.answer(
  ~H: String -> String -> List<&2, HTTP.Hdr> -> String -> IO(U32 & List<&1, String & String> & String),
  sock: Socket, request: HTTP1Request) -> IO(Unit):
  do IO<Unit>:
    response : HTTP1Response <- http1_apply(~H, request)
    text : String <- IO.pass(String, http1_show(response))
    sent : Socket & Result<&1, &1, (U32 & String), Unit> <-
      TLS.tls_send_bytes(sock, HTTP.encode(text))
    http1_serve.close_sent(sent)

def http1_serve.fail(sock: Socket, error: U32 & String) -> IO(Unit):
  do IO<Unit>:
    closed : Unit <- TLS.tls_close(sock)
    return Unit{}

@unsafe
def http1_serve(
  ~H: String -> String -> List<&2, HTTP.Hdr> -> String -> IO(U32 & List<&1, String & String> & String),
  phase: U32, got: Socket & Result<&1, &1, (U32 & String), List<&2, U32>>,
  parsed: Result<&1, &1, (U32 & String), HTTP1Request>,
  state: HTTP1ServeState, fuel: Nat) -> IO(Unit):
  match phase:
    case 0:
      (sock, result) = got
      match fuel:
        case 0n:
          http1_serve.fail(sock, (413, "request too long"))
        case 1n+rest:
          do IO<Unit>:
            next : Socket & Result<&1, &1, (U32 & String), List<&2, U32>> <-
              TLS.tls_recv_bytes(sock, 16384)
            http1_serve(~H, 1, next, parsed, state, rest)
    case 1:
      (sock, result) = got
      match result:
        case Fail{e}:
          http1_serve.fail(sock, e)
        case Done{part}:
          match part:
            case Nil{}:
              http1_serve.fail(sock, (400, "eof"))
            case h <> t:
              match state:
                case HTTP1ServeState{request, bytes, ready}:
                  +next : List<&2, U32> = List.append(&2, U32, bytes, part)
                  next_state : HTTP1ServeState = HTTP1ServeState{request,
                    next, ready}
                  http1_serve(~H, 2, (sock, Done{Nil{}}),
                    http1_request.parse(next), next_state,
                    http1_next_fuel(fuel))
    case 2:
      (sock, result) = got
      match parsed:
        case Fail{e}:
          do IO<Unit>:
            next : Socket & Result<&1, &1, (U32 & String), List<&2, U32>> <-
              TLS.tls_recv_bytes(sock, 16384)
            http1_serve(~H, 1, next, parsed, state,
              http1_next_fuel(fuel))
        case Done{parsed_request}:
          match parsed_request:
            case HTTP1Request{parsed_method, parsed_path,
              +parsed_headers, parsed_body}:
              match state:
                case HTTP1ServeState{state_request, +state_bytes, state_ready}:
                  +body : String = HTTP.body_of(HTTP.decode(state_bytes))
                  updated : HTTP1Request = HTTP1Request{parsed_method,
                    parsed_path, parsed_headers, body}
                  next_state : HTTP1ServeState = HTTP1ServeState{updated,
                    state_bytes, http1_serve.ready(parsed_headers, body)}
                  http1_serve(~H, 3, (sock, Done{Nil{}}),
                    Fail{(0, "")}, next_state,
                    http1_next_fuel(fuel))
    case 3:
      (sock, result) = got
      match state:
        case HTTP1ServeState{request, bytes, ready}:
          match ready:
            case True{}:
              http1_serve.answer(~H, sock, request)
            case False{}:
              do IO<Unit>:
                next : Socket & Result<&1, &1, (U32 & String), List<&2, U32>> <-
                  TLS.tls_recv_bytes(sock, 16384)
                http1_serve(~H, 1, next, parsed, state,
                  http1_next_fuel(fuel))
    case _:
      (sock, result) = got
      http1_serve.fail(sock, (616, "tls io"))

def http1_spawn(
  ~H: String -> String -> List<&2, HTTP.Hdr> -> String -> IO(U32 & List<&1, String & String> & String),
  sock: Socket, listener: Listener) -> IO(Listener):
  do IO<Listener>:
    empty : HTTP1Request = HTTP1Request{SNil{}, SNil{}, Nil{}, SNil{}}
    task : Unit <- IO.spawn(Unit, http1_serve(~H, 0,
      (sock, Done{Nil{}}), Fail{(0, "")},
      HTTP1ServeState{empty, Nil{}, False{}}, 64n))
    return listener

def http1_conn(
  ~H: String -> String -> List<&2, HTTP.Hdr> -> String -> IO(U32 & List<&1, String & String> & String),
  accepted: Listener & Result<&1, &1, (U32 & String), Socket>) -> IO(Listener):
  (listener, result) = accepted
  match result:
    case Fail{e}:
      IO.pure(Listener, listener)
    case Done{sock}:
      http1_spawn(~H, sock, listener)

@unsafe
def server_on_http1(
  ~H: String -> String -> List<&2, HTTP.Hdr> -> String -> IO(U32 & List<&1, String & String> & String),
  listener: Listener, +cert: String, +key: String) -> IO(Unit):
  do IO<Unit>:
    accepted : Listener & Result<&1, &1, (U32 & String), Socket> <-
      TLS.tls_accept_http1(listener, cert, key)
    next : Listener <- http1_conn(~H, accepted)
    server_on_http1(~H, next, cert, key)
