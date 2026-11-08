# contract (http2_api): the promised entries of lib/http2.bend (task-070
# phase 4). This file has no main, so check.sh reports it and never runs
# it; the typecheck is the gate. Each def names one promised entry with
# its full signature: a rename, a removed parameter or a changed return
# type breaks the typecheck here.
#
# Promised: the client and server entries below. Not promised: every
# x_* leaf. The tests may call a leaf, but a caller of the library calls
# an entry, and docs/h2-api.md records the same split.
#
# Version: 1 (see docs/h2-api.md). Adding an entry keeps the version.
# Removing or reshaping one raises it.
import Base
import ../../lib/http.bend as HTTP
import ../../lib/http2.bend as HTTP2

def api_client_connect(+host: String, +port: U32) -> IO(Result<&1, &1, U32 & String, Socket & HTTP.CliSt>):
  HTTP2.client.connect(host, port)

def api_client_connect_insecure(+host: String, +port: U32) -> IO(Result<&1, &1, U32 & String, Socket & HTTP.CliSt>):
  HTTP2.client.connect_insecure(host, port)

def api_client_once(+host: String, +port: U32, +req: HTTP.Request) -> IO(Result<&1, &1, U32 & String, HTTP.Response>):
  HTTP2.client.once(host, port, req)

def api_client_once_insecure(+host: String, +port: U32, +req: HTTP.Request) -> IO(Result<&1, &1, U32 & String, HTTP.Response>):
  HTTP2.client.once_insecure(host, port, req)

def api_client_on(+host: String, +port: U32, +reqs: List<&2, HTTP.Request>) -> IO(Result<&1, &1, U32 & String, List<&2, HTTP.Response>>):
  HTTP2.client.on(host, port, reqs)

def api_client_on_insecure(+host: String, +port: U32, +reqs: List<&2, HTTP.Request>) -> IO(Result<&1, &1, U32 & String, List<&2, HTTP.Response>>):
  HTTP2.client.on_insecure(host, port, reqs)

def api_client_concurrent(~H: HTTP.Response -> U32, +host: String, +port: U32, +reqs: List<&2, HTTP.Request>) -> IO(Result<&1, &1, U32 & String, U32>):
  HTTP2.client.concurrent(H, host, port, reqs)

def api_client_concurrent_insecure(~H: HTTP.Response -> U32, +host: String, +port: U32, +reqs: List<&2, HTTP.Request>) -> IO(Result<&1, &1, U32 & String, U32>):
  HTTP2.client.concurrent_insecure(H, host, port, reqs)

def api_client_request(sock: Socket, +st: HTTP.CliSt, +host: String, +port: U32, +req: HTTP.Request) -> IO(Socket & Result<&1, &1, U32 & String, HTTP.Response> & HTTP.CliSt):
  HTTP2.client.request(sock, st, host, port, req)

def api_request(+host: String, +port: U32, +path: String, +method: String, +hs: List<&2, HTTP.Hdr>, +body: String) -> IO(Result<&1, &1, U32 & String, String>):
  HTTP2.request(host, port, path, method, hs, body)

def api_request_insecure(+host: String, +port: U32, +path: String, +method: String, +hs: List<&2, HTTP.Hdr>, +body: String) -> IO(Result<&1, &1, U32 & String, String>):
  HTTP2.request_insecure(host, port, path, method, hs, body)

def api_request_bytes(+host: String, +port: U32, +path: String, +method: String, +hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  HTTP2.request_bytes(host, port, path, method, hs, body)

def api_request_bytes_insecure(+host: String, +port: U32, +path: String, +method: String, +hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  HTTP2.request_bytes_insecure(host, port, path, method, hs, body)

def api_fetch(+url: String) -> IO(Result<&1, &1, U32 & String, String>):
  HTTP2.fetch(url)

def api_fetch_insecure(+url: String) -> IO(Result<&1, &1, U32 & String, String>):
  HTTP2.fetch_insecure(url)

def api_fetch_bytes(+url: String) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  HTTP2.fetch_bytes(url)

def api_fetch_bytes_insecure(+url: String) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  HTTP2.fetch_bytes_insecure(url)

def api_client_stream_once(~H: HTTP.StreamEv -> HTTP.StreamOut, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  HTTP2.client.stream.once(H, host, port, method, path, hs, body)

def api_client_stream_once_insecure(~H: HTTP.StreamEv -> HTTP.StreamOut, +host: String, +port: U32, +method: String, +path: String, hs: List<&2, HTTP.Hdr>, +body: List<&2, U32>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  HTTP2.client.stream.once_insecure(H, host, port, method, path, hs, body)

def api_client_stream_on(~H: HTTP.StreamEv -> HTTP.StreamOut, +host: String, +port: U32, +reqs: List<&2, HTTP.Request>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  HTTP2.client.stream.on(H, host, port, reqs)

def api_client_stream_on_insecure(~H: HTTP.StreamEv -> HTTP.StreamOut, +host: String, +port: U32, +reqs: List<&2, HTTP.Request>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  HTTP2.client.stream.on_insecure(H, host, port, reqs)

def api_client_stream_concurrent(~H: HTTP.CStreamEv -> HTTP.CStreamOut, +host: String, +port: U32, +reqs: List<&2, HTTP.Request>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  HTTP2.client.stream.concurrent(H, host, port, reqs)

def api_client_stream_concurrent_insecure(~H: HTTP.CStreamEv -> HTTP.CStreamOut, +host: String, +port: U32, +reqs: List<&2, HTTP.Request>) -> IO(Result<&1, &1, U32 & String, U32 & U32>):
  HTTP2.client.stream.concurrent_insecure(H, host, port, reqs)

def api_client_loop_on(~H: HTTP.StreamEv -> HTTP.StreamOut, sock: Socket, +st: HTTP.CliSt, +host: String, +port: U32, reqs: List<&2, HTTP.Request>) -> IO(Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt):
  HTTP2.client.loop.on(H, sock, st, host, port, reqs)

def api_client_loop_exch(~H: HTTP.StreamEv -> HTTP.StreamOut, sock: Socket, +st: HTTP.CliSt, +host: String, +port: U32, req: HTTP.Request) -> IO(Socket & Result<&1, &1, U32 & String, U32 & U32> & HTTP.CliSt):
  HTTP2.client.loop.exch(H, sock, st, host, port, req)

def api_server_concurrent(~B: HTTP.Request -> IO(HTTP.Response), l: Listener, +cert: String, +key: String) -> IO(Unit):
  HTTP2.server.concurrent(B, l, cert, key)

def api_server_on(~B: HTTP.Request -> IO(HTTP.Response), l: Listener, +cert: String, +key: String) -> IO(Unit):
  HTTP2.server.on(B, l, cert, key)

def api_server_once(~B: HTTP.Request -> IO(HTTP.Response), l: Listener, +cert: String, +key: String) -> IO(Unit):
  HTTP2.server.once(B, l, cert, key)

def api_server_stream_concurrent(~H: HTTP.SrvEv -> HTTP.SrvOut, l: Listener, +cert: String, +key: String) -> IO(Unit):
  HTTP2.server.stream.concurrent(H, l, cert, key)

def api_server_stream_on(~H: HTTP.SrvEv -> HTTP.SrvOut, l: Listener, +cert: String, +key: String) -> IO(Unit):
  HTTP2.server.stream.on(H, l, cert, key)

def api_server_stream_once(~H: HTTP.SrvEv -> HTTP.SrvOut, l: Listener, +cert: String, +key: String) -> IO(Unit):
  HTTP2.server.stream.once(H, l, cert, key)
