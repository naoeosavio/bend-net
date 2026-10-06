# bend-net

HTTP/1.1 and WebSocket (RFC 6455) for [Bend](https://bend-lang.com),
written in user-land Bend on top of the `TCP.*` kit, with package-local
DNS and TLS (client + server, ALPN `h2` for the coming HTTP/2). The
native code is the byte-level socket effects, the A-record resolver and
the TLS effects in `lib/effs/` (OpenSSL via dlopen — no link flags).

## Layout

```text
lib/package.bend          # package entry (publish this file)
lib/http.bend             # HTTP/1.1 library (~2350 lines, imports Base only)
lib/wsm.bend              # WebSocket (WSM): ws:// + wss://, one implementation
lib/ws.bend               # WebSocket server + client (SUPERSEDED by wsm.bend)
lib/wss.bend              # WebSocket Secure: WS over TLS (SUPERSEDED by wsm.bend)
lib/sha1.bend             # SHA-1 (FIPS 180-4), for the handshake accept
lib/b64.bend              # base64, for the handshake accept
lib/static.bend           # static-file handler on top of HTTP
lib/tcp.bend              # byte-level socket effects (C + JS twins)
lib/dns.bend              # DNS resolve: A lookup for name hosts (C + JS twins)
lib/tls.bend              # TLS client + server effects (C + JS twins, OpenSSL)
lib/http2.bend            # HTTP/2 codec + client/server over TLS (pure Bend)
lib/https.bend            # HTTPS facade: fetch/send_request + server_on over TLS+DNS+H2
lib/https_http1.bend      # HTTP/1.1-only server module (chunked, ALPN http/1.1)
lib/httpx.bend            # HTTPX: H1 + H2 + HTTPS in one module (Base+tls only)
lib/effs/tcp_send_bytes.* # send List<&2, U32> over a Socket
lib/effs/tcp_recv_bytes.* # receive bytes from a Socket
lib/effs/tcp_recv_frame.* # isolate exactly one WS frame, rest preserved
lib/effs/dns_resolve.*    # resolve a host to one IPv4 (getaddrinfo / UDP query)
lib/effs/tls_*.{c,js}     # TLS connect/accept/send/recv/close (dlopen libssl)
tests/io/httpx_h1_pure.bend   # pure layer: URL, headers, framing, chunked, UTF-8
tests/io/httpx_h1_fetch.bend  # IO: real loopback fetch + fail-closed paths
tests/io/httpx_h1_fetch_host.bend # IO: fetch by name over loopback, Host preserved
tests/io/httpx_h1_sec.bend    # security: CRLF/NUL injection, oversize, bad status
tests/io/tcp_bytes.bend       # IO: send_bytes/recv_bytes over loopback
tests/io/tls_connect_close.bend # IO: TLS loopback echo + fail paths (611/612)
tests/io/h2_loopback.bend       # IO: HTTP/2 echo over TLS (Bend↔Bend)
tests/io/httpx_*.bend       # HTTPX: client, server, H1/H2 lanes, codec
tests/io/httpx_h1_*.bend    # the legacy lib/http.bend lane: pure, fetch, sec
tests/io/httpx_*_https.bend # fetch, streams, mux, H1 fallback — all on httpx
tests/io/wsm_*.bend         # WSM: the one WebSocket — crypto, codec, both lanes
tests/io/dns_resolve.bend     # DNS fast paths + fail-closed host checks
examples/                 # runnable interop programs (not published)
tasks/                    # engineering log (decisions, discoveries, checklists)
```

## Requirements

- Bend 2.0.21 or newer (`curl -fsSL https://bend-lang.com/install.sh | sh`).
- Always run from the repo root, so relative imports resolve.

## Use

Local import (relative to your file):

```bend
import Base
import ../../lib/http.bend as HTTP

def main() -> U32:
  HTTP.content_length([("Content-Length", "5")])
```

Hub import (after a publish, see below). Imports are not transitive, so the
entry only marks the bundle — import the API from its own file:

```bend
import Base
import 0x<hash>/http.bend as HTTP
```

## API

Pure layer (total, fail-closed — every parser answers `Result`):

| Function | Description |
|---|---|
| `read_url` | Parse `http(s)://host[:port]/path` into `secure & host & port & path` |
| `get_header` | Case-insensitive header lookup with default |
| `show_request` / `read_request` | Render / parse an HTTP request |
| `show_response` / `read_response` | Render / parse an HTTP response |
| `read_head` | Parse a request head, reporting the HTTP/1.1 flag |
| `keep_alive` / `with_connection` | Connection-persistence decision and stamping |
| `content_length` | Numeric `Content-Length`, defaulting to `0` |
| `unchunk` | `Transfer-Encoding: chunked` decoder (linear state machine) |
| `encode` / `decode` | Total UTF-8 encode / decode (`decode` repairs with `U+FFFD`) |
| `from_string` / `to_string` | Packed `U32 & bytes` conversions |
| `no_body` / `ok` | Empty body and `200` response helpers |

IO layer (every path closes its socket):

| Function | Description |
|---|---|
| `fetch` | `http://` GET with caps; `https://` is refused with `Fail 501` |
| `serve_once` | Serve one connection with a caller-provided handler |
| `echo.body` / `echo.serve` | Echo handler and its (unsafe) accept loop |
| `dispatch` / `route_status` | Handler dispatch and status projection |

Requests and responses are tuples: request is
`method & path & headers & body`, response is
`status & headers & body`, headers are `List<&1, String & String>`.

Binary socket effects (`lib/tcp.bend`, import as `TCP`) — the byte-level
twin of Base's `TCP.send`/`TCP.recv`, so frames never go through UTF-8:

| Function | Description |
|---|---|
| `send_bytes` | Send a `List<&2, U32>` (0–255); a value past 255 fails with `EINVAL` before any byte leaves; `EAGAIN` parks on `POLLOUT` |
| `recv_bytes` | Receive at most `max` bytes as `List<&2, U32>`; parks on `POLLIN` |
| `recv_frame` | Isolate exactly one WebSocket frame, seeded by `buf` (the previous rest); answers the frame plus every byte read past it, so no byte is lost. A total past `max` is `Fail 413`, a partial EOF `Fail 400 "eof"` |

All three hand the socket back as `Socket & Result<&1, &1, U32 & String, …>`
on every path.

## DNS

`lib/dns.bend` (import as `DNS`) resolves a host to one IPv4 dotted
quad, package-locally (`resolve(host) -> IO(Result<&1, &1, U32 & String,
String>)`). Canonical dotted quads and `localhost` answer without the
effect; everything else must pass the host checks (printable ASCII,
253 bytes at most, dot-labels 1–63) or fails with `Fail 601`.

Fail codes are stable numbers, never resolver text: `601` bad host,
`602` host not found, `603` resolve failed (try again), `604` no IPv4
address, `605` resolve error. The C twin rides `getaddrinfo` on a
helper thread; the JS twin writes one A query over UDP to the first
nameserver of `/etc/resolv.conf`, parking on the socket with a
deadline (one retry). `fetch` and `send_request` connect by the
resolved IP but send the ORIGINAL host in `Host` — virtual hosting
never changes. A dotted quad that fails the canonical check
(`256.1.1.1`, `01.2.3.4`) is asked as a NAME to the resolver (it fails
602/603, never connects as if it were an IP).

## TLS

`lib/tls.bend` (import as `TLS`) is a client and server TLS lane over
the byte effects, riding OpenSSL through `dlopen` (no link flags, both
the C and JS twins):

| Function | Description |
|---|---|
| `tls_connect(host, port)` | Resolve (DNS), connect and handshake with chain verification; SNI is the ORIGINAL host; ALPN `h2` is required |
| `tls_connect_insecure(host, port)` | Same handshake without chain verification (loopback/self-signed tests) |
| `tls_connect_noalpn(host, port)` / `tls_connect_noalpn_insecure` | Same without offering ALPN (WSS / HTTP/1.1 Upgrade over TLS) |
| `tls_accept(listener, cert, key)` | Accept one TCP connection and handshake it with the PEM cert/key files; ALPN `h2` preferred (NOACK when the client offers none) |
| `tls_send_bytes` / `tls_recv_bytes` | Byte-faithful send/recv (List<&2, U32>) over the TLS socket; WANT_READ/WANT_WRITE parks |
| `tls_close` | Orderly shutdown, session free, fd close |

Fail codes are stable numbers: `611` bad input (port/host), `612` dial
failed, `613` handshake failed, `614` verify failed, `615` ALPN
mismatch, `616` TLS IO error. The TLS handle is opaque (never a raw
fd): close it with `TLS.tls_close`, not `Socket.close`. DNS failures
keep the 601-605 codes and happen before any socket exists.

```sh
bend tests/io/tls_connect_close.bend   # 111
```

## HTTP/2

`lib/http2.bend` (import as `H2`) is a native HTTP/2 (RFC 7540/7541)
client and server riding the TLS lane — frames and HPACK are pure
Bend, no nghttp2/node:http2:

| Function | Description |
|---|---|
| `h2_connect(host, port)` / `h2_connect_insecure` | TLS dial, magic preface + SETTINGS |
| `h2_request(sock, sid, method, path, headers, body)` | One request/response exchange on stream `sid` (1, 3, 5, ...); the socket and next sid thread back |
| `h2_serve_once(sock, handler)` | Serve one request stream: preface, SETTINGS, HEADERS/DATA → `handler(H2Request) -> IO(H2Response)` → response frames |
| `h2_serve_next(sock, handler)` | Serve one more stream on an established connection (no preface); thread for sequential keep-alive (sid 1, 3, 5, ...) without a new handshake |

HPACK decodes the full RFC 7541 subset: literal (all three modes),
static-table indexed (1–61) and dynamic-table indexed references,
huffman strings (canonical Appendix B code), dynamic-table inserts
with eviction (entry = len + len + 32, max 4096) and table-size
updates. Integer continuations past 5 bytes fail closed with `502`
(RFC 7541 §7.4 implementation limit). The encoder stays literal
without huffman — valid HPACK every peer decodes, so Bend→Node needs
no huffman encoder. Header blocks split across CONTINUATION and
frames over 16384 still fail closed (`400`/`413`, backlog).
`examples/httpx_real.bend` is a manual smoke against live hosts
(observed 2026-09-28: example.com GET/POST OK, cloudflare.com
`fetch` OK on ~1.3 MB, info.cern.ch OK via H1);
it is never part of the gate. Multi-stream keep-alive clients against
huffman peers stay on single-shot `request` (fresh table per
connection, always correct); per-connection decode state threads
through the server loops and the concurrent mux.

```sh
bend tests/io/h2_loopback.bend         # 1
```

## HTTPS

`lib/https.bend` (import as `HTTPS`) is the public HTTPS facade over
TLS + DNS + the HTTP/2 codec — request/response/fetch plus generic
keep-alive servers, mirroring `lib/http.bend`:

| Function | Description |
|---|---|
| `request(host, port, method, path, hs, body)` / `request_insecure` | Single-shot exchange on stream 1 (connect + request + close); answers the full `H2Response` (status + headers + byte body) |
| `send_request(host, port, path, method, hs, body)` / `send_request_insecure` | Same exchange with a `String` body; answers the response body as `String` |
| `fetch(url)` / `fetch_insecure` | `https://` GET by URL (via `HTTP.read_url`); `http://` refused with `Fail 400`; answers the body as `String` |
| `fetch_bytes(url)` / `fetch_bytes_insecure` | Same GET answering raw `List<&2, U32>` bytes |
| `server_on(~H, l, cert, key)` | Generic keep-alive server (like `HTTP.server_on`): unbounded TLS accept loop with `IO.spawn` per connection, unlimited sequential streams per connection until GOAWAY/EOF; `~H` is `H2Request -> IO(H2Response)` |
| `server_on_concurrent(~H, l, cert, key)` | Same accept loop; per connection an unbounded interleaved mux (open streams tracked in a `List<H2SrvSt>` by sid, answered in any completion order; header fragments parked until CONTINUATION completes the block) |
| `server_on_alpn(~H2, ~H1, l, cert, key)` | Same, but ALPN splits the port: `h2` to the H2 codec, `http/1.1` to `lib/https_http1.bend` (same `IO.spawn` per connection) |
| `server_on_concurrent_alpn(~H2, ~H1, l, cert, key)` | ALPN split + unbounded interleaved mux |
| `mux_start(~H, sock)` | One-shot concurrent serve on an established TLS socket (the test entry of the mux) |
| `server_on_http1(~H, l, cert, key)` | HTTP/1.1-only server (the module of `lib/https_http1.bend`, ALPN `http/1.1` only) |

Bodies are byte-faithful `List<&2, U32>` at the core (`encode_body` /
`decode_body` wrap `H2.str_bytes` / `H2.bytes_str`); headers are
`List<H2Hdr>` (`pairs_to_h2` / `h2_to_pairs` convert http-style pairs).
Fail codes surface unchanged: `400/413/502/503` (codec), `601-605`
(DNS), `611-616` (TLS).

**Contract (2026-09-25, task-020):**

- `server_on` has **no fuel**: one accept loop serves streams until
  GOAWAY/EOF, the same contract `node:http2` expects.
- The client offers `h2` **and** `http/1.1` (ALPN mode 2) and speaks
  whichever the server picks; a peer without ALPN gets HTTP/1.1. The
  H1 lane lives in `lib/https_http1.bend`, reusing the pure codec of
  `lib/http.bend` with TLS as the only transport change, and answers
  byte-faithful (chunked and binary included).
- The server side splits on ALPN too: `tls_accept` is strict `h2`
  (legacy contract), `tls_accept_alpn` is dual, `tls_accept_http1` is
  H1-only.
- Flow control: the codec announces `INITIAL_WINDOW_SIZE=6 MB` and
  `MAX_FRAME_SIZE=65535`, replenishes the connection and stream
  windows on every inbound DATA, and slices uploads into
  `WINDOW_UPDATE`-paced frames. Bodies are not capped at 64 KB.
- Header blocks survive `CONTINUATION` in both directions, carry a
  per-response HPACK dynamic table on the client, and the 64-header
  fuel cap is gone (`512` fields, `512` HPACK tokens).
- `RST_STREAM`, `GOAWAY`, `PING` and `WINDOW_UPDATE` are handled as
  protocol events, not as skips; housekeeping frames are answered with
  a fresh-only `ACK` (never an ACK-of-an-ACK, which would ping-pong
  between two unbounded read loops).
- The frame reader has no read budget: it reads until a whole frame
  lands, so a peer that splits a frame over many TLS records (public
  sites deliver ~1.4 KB per record) no longer answers `400 eof`.

```sh
bend tests/io/httpx_fetch_https.bend   # 1
bend tests/io/httpx_streams.bend       # 1
bend tests/io/httpx_server_on.bend     # 1
bend tests/io/httpx_mux.bend           # 1
bend tests/io/httpx_http1_module.bend  # 1
bend tests/io/tls_alpn_dual.bend      # 1
bend tests/io/h2_frame_read.bend      # 8
bend examples/httpx_real.bend         # manual live smoke
```

## HTTPX (isolation)

`lib/httpx.bend` (import as `HTTPX`) is a standalone server + client with a
mini-H2 codec inside — imports `Base` + `tls` only, never `http2`/`https`.
It exists to isolate overhead (no Huffman rebuild per probe on the hot
path, no per-hop dynamic table, no flow-credit sends on the server); the
`## HTTPS` contract above is unchanged and keeps the full codec.
Architecture (the two delivery modes, why streaming handlers are pure):
`docs/modes.md`.

| Function | Description |
|---|---|
| `server.on(~H, l, cert, key)` / `server.on_alpn` | Sequential generic server (one stream at a time; pipelined HEADERS gets `RST_STREAM` 7) / ALPN split with one handler for both lanes |
| `server.on_h2(~H, l, cert, key)` / `server.on_h1(~H, l, cert, key)` | Mono-protocol forks: H2-only / H1-only (H1 lane is a local port of `http.bend` shapes: `Content-Length` **and** `Transfer-Encoding: chunked` framing, **keep-alive** — the server answers and reads the next request on the same connection until `connection: close`, EOF or a terminal 413/502) |
| `server.on_h1_plain(~H, l)` / `server.echo_h1_plain(l)` | The same keep-alive H1 server over plain TCP (`TCP.listen`/`accept`), no cert/key — the `http://` peer |
| `server.once(~H, l, cert, key)` / `server.once_h1(~H, l, cert, key)` | Accepts **one** connection and stops (no recursion) — the entry a test or single-shot server wants; `once_h1` is the `http/1.1` pair |
| `server.echo(l, cert, key)` / `server.echo_alpn` | The fixed echo server: status 200, no headers, the request body back (`echo_body`) |
| `server.concurrent(~H, l, cert, key)` / `server.concurrent_alpn` | Interleaved httpx echoing `Request -> IO(Response)` (slots by sid, any completion order; `_alpn` is H2-only, non-H2 closes — use `server.on_alpn` for the H1 split) |
| `server.stream(~H, l, cert, key)` / `server.stream_alpn` | Upload streaming: `SrvReqHead`/`SrvReqData` events to a pure `~H`, `Continue` buffers, `RespondEarly` answers without draining |
| `client.once(_insecure)(host, port, Request)` | One-shot: dial + one `client.request` + close. `client.request` dispatches both ALPN answers, so the H1 leg needs nothing of its own |
| `client.on(_insecure)(host, port, reqs)` | Sequential batch entry: one dial, N requests, answers in order; first `Fail` aborts. H2 keeps sids 1, 3, 5, ... and the HPACK table; an `http/1.1` connection reuses the one socket through the H1 lane (`client_seq.h1`) |
| `client.echo(_insecure)(host, port, path)` | A disposable `GET` over `client.once` |
| `client.connect(_insecure)(host, port)` | Hands back `Socket & CliSt{sid, tab, is_h2}`. `client.request(sock, st, host, port, req)` is **one** exchange on it, both ALPN answers, and it **never closes**: the caller closes (`client.on`/`client.once` do) or calls again for the next request, threading the socket and the state — the returned `CliSt` carries the advanced sid and the HPACK table the next response decodes against. N requests are that loop at the call site |
| `client.concurrent(_insecure)(~H, host, port, reqs)` | Pipelined N requests (sids 1, 3, 5, 7, ...) drained through slots, scored by `~H: Response -> U32` |
| `client.stream(_insecure)(~H, host, port, ...)` | Download streaming with a pure `~H` (`StreamHead`/`StreamData`); `StreamCancel` sends `RST_STREAM` |
| `request(_insecure)` | Any method with headers and a `String` body over `client.once`; answers the response body as `String` |
| `request_bytes(_insecure)` | Same with raw-bytes body in and out |
| `fetch(_insecure)` / `fetch_bytes(_insecure)` | GET by URL over `httpx_url.read_url` (ported from `http.bend`, no import); `http://` is served by `_insecure` over the plaintext H1 lane, and refused `400` when verifying |
| `h1_once(_insecure)` | Single-shot over the H1 lane (no-ALPN dial, WSS-style) |

Limits (fail-closed, by design): responses are literal-only, DATA sliced
to conn+stream windows (pump v2, no 16 KB cap); `WINDOW_UPDATE` credit
flows both directions (server per DATA, streaming-download client per
non-final DATA, else >64 KB stalls); fragmented header blocks
(CONTINUATION) reassemble inline-blocking on all three client drains
and on `httpx_stream` (RFC 9113 §6.10 forbids interleave mid-sequence, so
no per-stream ledger); Huffman/dynamic-table peers decode (static 1–61,
literal, Huffman strings, minimal dyn table), which is what `node:http2`
needs; H1 headers are checked at render time — a CR/LF/NUL in a name or a
value is refused (`Fail` 400 on a request, a bare 500 on a response)
instead of ending the field early and shipping the rest as headers nobody
asked for. The H1 lane decodes `Transfer-Encoding: chunked` in **both**
directions (TASK-033): one step machine (`x_h1.chunk_step`, ported from
`lib/web/http/main.bend`'s `h1_chunk_step`) feeds the client body reader
and the two server request readers, bodies are copied in blocks instead of
byte by byte, and the caps are the lane's own — client fuel (413
`response too long`), server fuel (413 `request too long`) and the server's
16384-byte body cap (413). Fail-closed: a truncated chunk, a non-hex size, a
trailer section and bytes after the terminator are all `400` (`bad chunked`
on the server answer, `eof` for a peer that closes mid-body), never a partial
body read as a whole one. A hex size that does not fit the U32 counter is not
guarded explicitly — the same as the reference machine — but it cannot become
a silently wrong body: the measured vector answers `400`, because a wrapped
size no longer matches the bytes that follow it.

```sh
bend tests/io/httpx_miniunit.bend         # 1 (pure frame + HPACK roundtrip, ~2s)
bend tests/io/httpx_client.bend           # 1 (once vs mini server)
bend tests/io/httpx_interop.bend          # 1 (4 crossed streams vs mini server)
bend tests/io/httpx_client_once.bend      # 1
bend tests/io/httpx_client_keepalive.bend # 3
bend tests/io/httpx_client_request.bend   # 7 (4 chained + reset + H1 reuse)
bend tests/io/httpx_client_concurrent.bend # 4
bend tests/io/httpx_client_stream.bend    # 1
bend tests/io/httpx_server_stream.bend    # 2
bend tests/io/httpx_read_url.bend         # 1 (pure URL vectors)
bend tests/io/httpx_fetch.bend            # 1 (fetch by URL vs mini server)
bend tests/io/httpx_client_seq.bend       # 3 (batch entry vs mini server)
bend tests/io/httpx_server_seq.bend       # 2 (terminal requests vs sequential server)
bend tests/io/httpx_http1_fallback.bend   # 1 (dual client vs H1 server)
bend tests/io/httpx_server_alpn.bend      # 2 (ALPN split, H2 + H1 clients)
bend tests/io/httpx_echo_once.bend        # 2 (server.once + server.echo, client.once/echo)
bend tests/io/httpx_plain_h1.bend         # 2 (http:// end to end over server.on_h1_plain)
bend tests/io/httpx_h1_keepalive.bend     # 14 (H1 close policy + reuse + client batch + terminal)
bend tests/io/httpx_flow.bend             # 1 (25 KB up+down through pump v2 + WU credit)
bend tests/io/httpx_client_cont.bend      # 1 (fragmented HEADERS+CONT vs once drain)
bend tests/io/httpx_client_cont_stream.bend # 1 (same peer vs streaming drain, no double-Head)
bend tests/io/httpx_client_cont_conc.bend # 1 (same peer vs concurrent drain)
bend tests/io/httpx_concurrent_cont.bend  # 1 (fragmented HEADERS+CONT vs httpx loop)
bend tests/io/httpx_server_cont.bend      # 1 (fragmented HEADERS+CONT vs httpx_stream)
bend tests/io/httpx_request.bend     # 2 (String + bytes bodies vs mini server)
```

## WebSocket (WSM)

`lib/wsm.bend` (import as `WSM`) is **one** RFC 6455 implementation for
both schemes. The handshake rides the H1 upgrade lane of
`lib/httpx.bend` (the `101` detaches the socket: `h1_open` on the client,
`on_h1_open` on the server) and the frames ride `lib/tls.bend` /
`lib/tcp.bend` directly once the socket is handed over. Nothing in the
module imports `ws.bend`, `wss.bend` or `http.bend`: the codec (frames,
mask, close, ping/pong, fragments, UTF-8) and the handshake live in the
module. `lib/ws.bend` and `lib/wss.bend` are **superseded** — they stay
for old callers only, and the whole loop/handshake/split existed twice
there (once over `TCP.*`, once over `TLS.*`), which is the cost this
module removes.

**Lanes are picked by name.** TLS keeps the short name, cleartext gets
`_plain`, and `_insecure` always means "does not verify" — never "no
TLS".

| TLS (`wss://`) | Cleartext (`ws://`) |
|---|---|
| `server_on(~H, l, cert, key)` | `server_on_plain(~H, l)` |
| `server_on_sub(~H, wanted, l, cert, key)` | `server_on_sub_plain(~H, wanted, l)` |
| `serve_once(sock)` | `serve_once_plain(sock)` |
| `client_on(~H, host, port, path, key)` | `client_on_plain(~H, host, port, path, key)` |
| `client_on_insecure(...)` | — (cleartext never verifies) |
| `client_on_sub(~H, host, port, path, key, protos)` / `client_on_sub_insecure(...)` | `client_on_sub_plain(...)` |
| `client_echo(host, port, path, key, msg)` / `client_echo_insecure(...)` | `client_echo_plain(...)` |

The `cert`/`key` pair exists **only** on the TLS server entries: the
`_plain` twins take no certificate at all, because cleartext is reached
by name, not by a flag. The same for verification on the client: the
`_insecure` suffix is the only way to skip it. `~H` is the same handler
in both lanes: `WSEv -> IO(WSOut)`, one step per frame, one `EvOpen`
after the handshake.

Handshake (pure):

| Function | Description |
|---|---|
| `wsm_accept_of` | `Sec-WebSocket-Accept` = base64(SHA1(key ++ GUID)) |
| `wsm_validate` / `wsm_validate_sub` | Validate parsed headers (GET, `Upgrade`, `Connection`, `Version`, `Key`) and pick a subprotocol |
| `wsm_accept_hdrs` / `_sub` | The `101` headers as `HTTPX.Hdr` (the lane renders the head) |
| `wsm_client_request` / `_sub` | The client upgrade request as `HTTPX.Request` (the lane injects the `Host`, always `host:port`) |
| `wsm_client_ok` / `_sub` | Validate the `101` plus the echoed `Accept` (and the picked subprotocol) |
| `wsm_handshake` / `_sub`, `wsm_show_101` / `_sub`, `wsm_client_head` / `_sub` | Text surface over the same rules, for callers that speak the head as `String` |

Frame codec (pure, bytes are `List<&2, U32>`):

| Function | Description |
|---|---|
| `wsm_read_frame` / `wsm_read_frame_unmasked` | Parse one frame into `fin & op & payload`; masked / unmasked |
| `wsm_show_frame` / `wsm_show_masked` (`_key`, `_random`) | Render an unmasked frame / a client-masked frame |
| `wsm_frame_need` / `wsm_frame_split` (+ `_unmasked`) | Length-prefix size, and incremental split into `HTTPX.UnitOut` (`Got` / `NeedMore` / `Bad` / `End`); a partial frame is never materialized |
| `wsm_unmask` | XOR a payload with the four mask bytes |
| `wsm_utf8_encode` / `_decode` / `_ok` | The `WSText` lane (RFC 3629, strict) |

Messages and events: `WSMessage` is `WSText{text}` or `WSBin{data}`;
`WSOut` is `OutMsg` / `OutOp` / `OutRaw`; `WSIn` is `InMsg` / `InOp`;
`WSEv` is the lifecycle event (`EvOpen`, `EvMsg`, `EvPing`, `EvPong`,
`EvClose`, `EvError`); `WsStep` and `MsgAcc` are loop internals, `WSMask`
the client key. The names mirror `lib/websocket/type.bend`, so the move
between the two trees is a requalification, not a redesign.

IO — the template defs take the transport as `~recv` / `~send`, and the
instances pin one lane (never an `is_tls` flag):

| Function | Description |
|---|---|
| `wsm_recv_frame(~recv, s, buf, unmasked_ok)` | One frame per call; the rest threads back as the next `buf` |
| `wsm_recv_in(~recv, s, buf, unmasked_ok)` | One read as `WSIn` (`InMsg` for data, `InOp` for control/fragmented) |
| `wsm_send_open(~send, is_client, s, out)` | One `WSOut`; the socket stays open, the loop owns the close |
| `wsm_send_bytes(~send, m)` | Ship a framed-bytes result verbatim |
| `send_msg_plain` / `send_op_plain` / `send_msg_tls` / `send_op_tls` | Masked client send, one line per lane |
| `wsm_ship_plain` / `wsm_ship_tls` | Send-and-close, the shape the old `ws.send_bytes` had |
| `recv_op[_client]_framed_plain`, `recv_msg[_client]_framed_plain`, `send_open_{op,msg,bytes}_plain`, `recv_bytes_plain` | The retired `lib/ws.bend` vocabulary, one line each over the templates (compat for importers) |
| `client_scan_len`, `ws_host_port` | Pure compat helpers: the head length up to the CRLFCRLF terminator, and the **retired** `Host` rule (default port omitted — the wire always renders `host:port`) |

**Close state (2026-09-25, task-020):** the close handshake is
complete. An empty close payload reports `1005` to the application but
never puts `1005` on the wire (the echo of an empty close used to make
Node answer `1002`); a 2-byte payload is validated (2 bytes, known
code, UTF-8 reason, `1005/1006/1015` refused); text frames and close
reasons are validated as UTF-8, so a peer answers `1007` instead of
silently accepting replacement characters. Fragments are reassembled
(`1/2` then `0*` until `FIN=1`) in both directions, and the payload cap
(`16 MB`) answers `close 1009` instead of a bare TCP close.

Fail codes surface unchanged: WS `400`/`413`, DNS `601-605`, TLS
`611-616`.

```sh
bend tests/io/wsm_loopback.bend       # 3   (plain + TLS session + one-shot TLS)
bend tests/io/wsm_upgrade_rest.bend   # 3   (head+frame in one write)
bend tests/io/wsm_surface.bend        # 29  (pure text surface + UTF-8)
bend tests/io/wsm_compat.bend         # 9   (the _plain compat instances)
bend tests/io/wsm_loopback_tls.bend   # 111
bend tests/io/wsm_server_on.bend      # 1
bend tests/io/wsm_client_on.bend      # 1111
bend tests/io/wsm_close.bend          # 10
bend tests/io/wsm_fragments.bend      # 9
bend tests/io/wsm_handshake_sub.bend  # 12

bend examples/wsm_binance_bookticker.bend | head   # live public peer
```

## Helpers

| Module | Function | Description |
|---|---|---|
| `lib/sha1.bend` (`SHA1`) | `sha1(bytes)` | FIPS 180-4 digest of a byte list |
| `lib/b64.bend` (`B64`) | `encode(bytes)` / `decode(string)` | base64 over byte lists |
| `lib/static.bend` (`Static`) | `safe_read(root, path)` | Read a file under `root`, refusing `..`, absolute paths, CRLF and NUL |
| | `content_type(path)` | Content-Type from the file extension |

## Examples

`examples/` holds runnable programs that are not part of the package:
`http_real.bend` fetches live pages through `lib/http.bend`;
`https_real.bend` is the HTTPS smoke (manual; example.com OK,
cloudflare.com plain `fetch` on ~1.3 MB, info.cern.ch via H1 —
may still `Fail` closed on other peers: HPACK subset / CONTINUATION); `server.bend` / `cliente.bend` are the
hand-driven WS session;
`server_on.bend` / `cliente_on.bend` are the same session over the
`server_on` / `client_on` event API; the `.js` files are `ws` npm peers
used for the interop matrix (WSS/HTTPS peers live alongside them).
`saturate_https_wss.bend` is the manual load driver (20 parallel
clients per lane over ephemeral ports; prints `SAT`/`BENCH` lines) —
never runs in the gate.
`wss_binance_bookticker.bend` is the live public-peer probe: it dials
`wss://stream.binance.com:9443/ws` with `client_on` (real TLS, cert
verified), sends one `SUBSCRIBE` frame for `bnbusdt@bookTicker` and
prints a `BOOK` line per update (symbol, best bid/ask price and size)
until the 15 s sleep in `main` halts the run — pipe it through `head`.

HTTPX interop (`lib/httpx.bend`, manual only — never in the gate):
`httpx_echoserv.bend` serves the mini-H2 echo on an ephemeral port
(printed to stdout; binary builds in <45s);
`httpx_server_stream.bend` serves the streaming-upload cap-3 handler on
an ephemeral port; `httpx_client_once.bend` dials a node echo server
(`mux_node_echoserv.js 19893 1`) with `client.once_insecure` and checks
status 200 + echo; `mux_node_client.js [port] [n]` fires N concurrent
POSTs on one `node:http2` session (`DONE n/2N+2`);
`mux_node_echoserv.js [port] [n]` is the H2-only echo for Bend clients;
`mux_node_bigserv.js [port] [n]` answers 100 KB for streaming-download
clients. Measured 2026-09-27: N=20 `DONE 42/42` under node and bun
against the C binary server; `httpx_client_once_bulk.bend` GETs the live
Binance `exchangeInfo` feed (~5.8 MB JSON) via `client.once` and
prints status + length + head — measured 2026-09-28: `STATUS 200
LEN 5851449 DONE 3/3` (build the C binary first, interp is too slow
for multi-MB bodies).
`httpx_fetch_bulk.bend` GETs the live
Binance `exchangeInfo` feed (~5.8 MB JSON) via `fetch_bytes` and
prints length + head — measured 2026-09-28: `LEN 5851449 DONE 2/2`
(build the C binary first, interp is too slow
for multi-MB bodies).

Every WS peer runs the same scripted 6-step session on `127.0.0.1:19880`
(`/chat`): `101 -> ping s1/pong -> ping c1/pong -> hello/echo ->
ping s2/pong -> close`. Run one server at a time from the repo root;
each side prints one `OK` line per step and `DONE 6/6`
(pass = `DONE` present with no `FAIL`).

```sh
bend examples/server.bend        # then: bend examples/cliente.bend
bend examples/server_on.bend     # then: bend examples/cliente_on.bend
# ws peers need `ws` resolvable under node (bun uses its builtin):
NODE_PATH=/tmp/wsport/node_modules node examples/server.js 19880
NODE_PATH=/tmp/wsport/node_modules node examples/client.js 19880
bun examples/server.js 19880      # all four ws peers also run under bun
node examples/server_native.js 19880   # no dependencies (also runs under bun)
node examples/client_native.js 19880   # no dependencies (also runs under bun)
```

Any server talks to any client (`server.bend <-> client.js`,
`cliente.bend <-> server.js`, `server_on.bend <-> client_native.js`,
`cliente_on.bend <-> server_native.js`, ...). `check.sh --checks`
typechecks the `.bend` files and syntax-checks the `.js` files;
`http_real.bend` is a manual smoke test of live sites BY NAME (it
needs a working resolver) and never runs in the gate.

Interop matrix (loopback, test PEMs; measured 2026-09-22/23 in
`tasks/task-018`/`task-020` — re-run pending on the CI box):

| Pair | Result |
|---|---|
| WSS node ↔ node / bun ↔ bun / node ↔ bun / bun → node | **4/4 PASS** |
| Bend `httpx_echo_client` → Node `https_server.js` | **PASS** (`DONE 3/3` / `DONE 1/1`) |
| Node `https_client.js` → Bend `httpx_echo_server.bend` | **PASS** (`DONE 4/4`; was `502 huffman refused` before HPACK-full) |
| Bend ↔ Bend HTTPS | **PASS** (golden `tests/io/httpx_*_https.bend`, 4/4) |
| HPACK vectors (RFC C.4.1/C.6.1) + dynamic-table unit | **PASS** (`tests/io/hpack_huffman.bend` 11111111, `hpack_dyntab.bend` 11111111) |

## Security policy

- `show_*` rejects CRLF in every field with `Fail 400` (injection).
- `read_*` caps the head at 16 KB; oversize is `Fail 413`.
- Ports must be 1–65535; hosts reject whitespace, controls and NUL.
- `fetch` reads at most 8 × 8192 bytes (64 KB cap), then truncates.
  The HTTPS lane (`lib/https.bend`) has no such cap: it streams with
  HTTP/2 flow control and a 16 MB WebSocket payload cap.
- Client WebSocket frames are masked with a key drawn from the host
  entropy pool (`IO.random_u32` → `getrandom`/`arc4random`, RFC 6455
  §5.3). `show_masked(fin, op, payload, k0..k3)` stays public for tests
  that want a fixed key on purpose; no production path uses it.
- Name hosts resolve via `lib/dns.bend` (fail-closed, `Fail 601`–`605`);
  the resolved IP is transport-only — `Host` keeps the original name.
- TLS verifies the chain and the hostname (`SSL_set1_host`) and SNIs
  the original host; there is no custom-CA, client-cert or SNI-override
  API, only `*_insecure` (`verify=False`) for loopback.

## Publish

One command uploads `lib/package.bend` with everything it imports and prints
the import lines. No sign-up: proof of work takes its place. No `TODO` or
open law can land (`law fetch` is filled by `def fetch`; the `@unsafe`
defs are the HTTP echo and WS accept/event loops; the byte effects carry
their `.c`/`.js` twins).

```sh
bend lib/package.bend --publish
# 0x<hash>
# import 0x<hash>/http.bend as HTTP
# import 0x<hash>/ws.bend   as WS
# import 0x<hash>/sha1.bend as SHA1
# import 0x<hash>/b64.bend  as B64
# import 0x<hash>/tcp.bend  as TCP
```

The first run of an importer fetches the package from the hub into
`~/.bend/lib` and checks it against its hash; later runs read the cache
and never go online. Every fix is a new hash — consumers upgrade by
pasting the new line.

## Tests

```sh
bend tests/io/httpx_h1_pure.bend        # 481441153
bend tests/io/httpx_h1_sec.bend         # 15
bend tests/io/httpx_h1_fetch.bend       # 111
bend tests/io/httpx_h1_fetch_cl.bend    # 111
bend tests/io/httpx_h1_fetch_post.bend  # 111
bend tests/io/httpx_h1_fetch_head.bend  # 11111
bend tests/io/httpx_h1_fetch_host.bend  # 111
bend tests/io/httpx_h1_server_on.bend   # 111
bend tests/io/tcp_bytes.bend          # 11
bend tests/io/tcp_bytes_loopback.bend # 1
bend tests/io/dns_resolve.bend        # 1111111111
bend tests/io/tls_connect_close.bend  # 111
bend tests/io/h2_loopback.bend        # 1
bend tests/io/httpx_fetch_https.bend   # 1
bend tests/io/httpx_streams.bend       # 1
bend tests/io/httpx_server_on.bend     # 1
bend tests/io/httpx_mux.bend           # 1
bend tests/io/wsm_crypto.bend          # 8
bend tests/io/wsm_handshake.bend       # 4
bend tests/io/wsm_frame.bend           # 6
bend tests/io/wsm_unmasked.bend        # 4
bend tests/io/wsm_loopback_plain.bend  # 111
bend tests/io/wsm_msg.bend             # 1111
bend tests/io/wsm_framing.bend         # 13
bend tests/io/wsm_framed.bend          # 4
bend tests/io/h2_flow.bend            # 11
bend tests/io/h2_rst.bend             # 13
bend tests/io/hpack_continuation.bend # 30
bend tests/io/h2_frame_read.bend      # 8
bend tests/io/httpx_http1_module.bend # 1
bend tests/io/tls_alpn_dual.bend      # 1
bend tests/io/wsm_close.bend            # 10
bend tests/io/wsm_fragments.bend        # 9
bend tests/io/wsm_handshake_sub.bend    # 12
bend tests/io/wsm_mask.bend             # 19
bend tests/io/wsm_client_coalesce.bend  # 1
bend tests/io/wsm_loopback.bend         # 3   (plain + TLS session + one-shot TLS)
bend tests/io/wsm_upgrade_rest.bend     # 3   (101 + first frame in one write)
bend tests/io/wsm_surface.bend          # 29  (pure text surface + UTF-8)
bend tests/io/wsm_compat.bend           # 9   (the _plain compat instances)
bend tests/io/httpx_miniunit.bend           # 1
bend tests/io/httpx_client.bend             # 1
bend tests/io/httpx_interop.bend            # 1
bend tests/io/httpx_client_once.bend        # 1
bend tests/io/httpx_client_keepalive.bend   # 3
bend tests/io/httpx_client_request.bend     # 7   (4 chained + reset + H1 reuse)
bend tests/io/httpx_client_concurrent.bend  # 4
bend tests/io/httpx_client_stream.bend      # 1
bend tests/io/httpx_server_stream.bend      # 2
bend tests/io/httpx_read_url.bend           # 1 (pure URL vectors)
bend tests/io/httpx_fetch.bend              # 1 (fetch by URL vs mini server)
bend tests/io/httpx_client_seq.bend         # 3 (batch entry vs mini server)
bend tests/io/httpx_server_seq.bend         # 2 (terminal requests vs sequential server)
bend tests/io/httpx_http1_fallback.bend     # 1 (dual client vs H1 server)
bend tests/io/httpx_server_alpn.bend        # 2 (ALPN split, H2 + H1 clients)
bend tests/io/httpx_flow.bend               # 1 (25 KB up+down through pump v2 + WU credit)
bend tests/io/httpx_client_cont.bend        # 1 (fragmented HEADERS+CONT vs once drain)
bend tests/io/httpx_client_cont_stream.bend # 1 (same peer vs streaming drain, no double-Head)
bend tests/io/httpx_client_cont_conc.bend   # 1 (same peer vs concurrent drain)
bend tests/io/httpx_concurrent_cont.bend      # 1 (fragmented HEADERS+CONT vs httpx loop)
bend tests/io/httpx_h1_keepalive.bend       # 14 (H1 close policy + reuse + client batch + terminal)
bend tests/io/httpx_h1_chunk.bend           # 35 (pure chunked decoder: vectors, step, reference equivalence)
bend tests/io/httpx_h1_fetch_chunk.bend     # 8 (chunked response end to end, truncated -> 400)
bend tests/io/httpx_h1_server_chunk.bend    # 6 (chunked request end to end: 200, 400, 413, keep-alive, upgrade lane)
bend tests/io/httpx_h1_upgrade.bend         # 7 (101 detaches the socket: server + client)
bend tests/io/httpx_h1_upgrade_client.bend  # 7 (renderer + raw peer + 200 -> 502)

bend tests/io/httpx_request.bend       # 2 (String + bytes bodies vs mini server)
bend tests/io/core_contract.bend          # 1 (core contract + header helpers + Fail codes)
bend tests/io/core_read_url.bend          # 1 (core URL vectors + valid_* gates)
```

Each file ends with a `#|` line holding the expected output. That line is the
golden, but `bend` itself does not compare it: a test that prints something
else still exits 0, so capture stdout and diff it (as `.p26/suite.sh` does)
instead of trusting the exit status alone. A file with no `main` (like
`lib/package.bend`) instead prints `All terms check.`; the echo server's
`@unsafe` annotation is expected.
JS and C lanes:

```sh
bend tests/io/httpx_h1_pure.bend -o /tmp/pure.js && bun /tmp/pure.js
bend tests/io/httpx_h1_pure.bend -o /tmp/purebin && /tmp/purebin
```

## Note on the byte effects and `lib/tcp.bend` / `lib/dns.bend`

`lib/wsm.bend` and `lib/ws.bend` import `./tcp.bend as TCPB` / `as TCP`
and call `TCP.send_bytes` / `TCP.recv_bytes` / `TCP.recv_frame`;
`lib/http.bend` imports `./dns.bend as DNS` and calls `DNS.resolve`.
Keeping the effects in the package (rather than in `Base`) is what makes
the bundle self-contained: a hub consumer with a stock Base can
`import 0x<hash>/lib/wsm.bend as WSM` (or the superseded
`0x<hash>/lib/ws.bend as WS`) and compile.

The effect host symbols are the defs' local names — `send_bytes_run`,
`recv_bytes_run`, `recv_frame_run`, and the JS functions `send_bytes`,
`recv_bytes`, `recv_frame` — while the `TCP` in a call site comes from
the import alias. The same holds for the resolver: the effect def is
`dns_lookup` (`dns_lookup_run` / `dns_lookup`, `CID_DNS_LOOKUP`) and the
public `resolve` is a pure wrapper in `lib/dns.bend`. (A def named
`TCP.recv_frame` would instead compile to the host `tcp_recv_frame`;
that is the shape of the parallel `bend2/` Base patch, so the two trees
are not interchangeable.)

The C side targets the Bend 2.0.21 runtime: `io_wait_on(w, fd, evts,
time, more)` takes the deadline word (pass `0`), and `io_node` takes
four arguments.

## Roadmap

- HTTPS/WSS validation (done 2026-09-22, see `tasks/task-018-validate-https-wss.md`):
  interop WSS 4/4 + Bend→Node HTTPS PASS (Node→Bend FAIL documented:
  HPACK huffman), saturation 20/20 per lane
  (`examples/wsm_saturate.bend`), bench 40 exchanges in ~15.2s
  interp / ~2.3s C (~2.6 vs ~17.8 ex/s).
- HPACK full (done 2026-09-22, see `tasks/task-019-hpack-huffman-dyntab.md`):
  huffman decode + dynamic table + table-size updates; interop HTTPS
  bidirecional PASS; saturation 20/20 per lane (interp ~16.3s / C
  ~2.2s for 40 exchanges — see `tasks/task-023-perf.md`).
- HTTP/2 done (task-020, 2026-09-25): unbounded-slot interleaved mux,
  CONTINUATION, flow control with `WINDOW_UPDATE` (connection and
  stream), `MAX_FRAME_SIZE=65535`, `RST_STREAM`/`GOAWAY`/`PING` as
  protocol events, HPACK dynamic table on the client, ALPN HTTP/1.1
  fallback on the same port. Still out: h2c (cleartext), server push,
  HPACK Huffman *encode* (literal-only is valid), `PRIORITY`.
- Open: the client HPACK dynamic table is per response, so a
  keep-alive connection does not reuse entries across responses;
  trailers and 1xx informational responses are not surfaced; there is
  no idle timeout on `keep-alive`.
- IPv6 (AAAA) resolution and connect: `dns.bend` answers A only.
- Cluster run of the suite (`--gate`) and a first hub `--publish`.
- Performance (task-023, DEFERRED): runs after the remaining tasks.
