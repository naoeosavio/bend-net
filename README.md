# bend-net

HTTP/1.1, HTTP/2 and WebSocket (RFC 6455) for [Bend](https://bend-lang.com).
The library is user-land Bend on top of the `TCP.*` kit. It has
package-local DNS and TLS (client + server, ALPN `h2` + `http/1.1`).

The native code is the byte-level socket effects, the A-record resolver
and the TLS effects in `lib/effs/`. Each effect ships two twins. The C
twin (OpenSSL through `dlopen`, no link flags) is for the native binary
target. The JS twin is for every other lane.

The TLS JS twins ride one portable runtime. That runtime is
`lib/effs/tls_rt.js` (TLS 1.2 + 1.3 in pure JS over the host's `crypto`
builtins, no `bun:ffi`, no libssl). `docs/tls-dns.md` gives the build
history of the lanes and the reasons; `tests/effs/` is the lab that
proves them.

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
lib/tls.bend              # TLS client + server effects (C = OpenSSL, JS = portable)
lib/effs/tls_rt.js        # the portable TLS runtime the JS twins load (TLS 1.2+1.3)
lib/http2.bend            # HTTP/2 codec + client/server over TLS (pure Bend)
lib/https.bend            # HTTPS facade: fetch/send_request + server_on over TLS+DNS+H2
lib/https_http1.bend      # HTTP/1.1-only server module (chunked, ALPN http/1.1)
lib/httpx.bend            # HTTPX: H1 + H2 + HTTPS in one module (Base+tls only)
lib/effs/tcp_send_bytes.* # send List<&2, U32> over a Socket
lib/effs/tcp_recv_bytes.* # receive bytes from a Socket
lib/effs/tcp_recv_frame.* # isolate exactly one WS frame, rest preserved
lib/effs/dns_resolve.*    # resolve a host to one IPv4 (getaddrinfo / UDP query)
lib/effs/tls_*.{c,js}     # TLS connect/accept/send/recv/close (C: OpenSSL; JS: tls_rt.js)
tests/io/tls_*.bend           # TLS loopback lanes + ALPN contracts (dual, none)
tests/effs/                   # the effects lab: parity lint, TLS ladders, bridge probe, bench
tests/io/httpx_h1_pure.bend   # pure layer: URL, headers, framing, chunked, UTF-8
tests/io/httpx_h1_fetch.bend  # IO: real loopback fetch + fail-closed paths
tests/io/httpx_h1_fetch_host.bend # IO: fetch by name over loopback, Host preserved
tests/io/httpx_h1_sec.bend    # security: CRLF/NUL injection, oversize, bad status
tests/io/tcp_bytes.bend       # IO: send_bytes/recv_bytes over loopback
tests/io/tls_connect_close.bend # IO: TLS loopback echo + fail paths (611, refused dial)
tests/io/h2_loopback.bend       # IO: HTTP/2 echo over TLS (Bend↔Bend)
tests/io/httpx_*.bend       # HTTPX: client, server, H1/H2 lanes, codec
tests/io/httpx_h1_*.bend    # the legacy lib/http.bend lane: pure, fetch, sec
tests/io/httpx_*_https.bend # fetch, streams, mux, H1 fallback — all on httpx
tests/io/wsm_*.bend         # WSM: the one WebSocket — crypto, codec, both lanes
tests/io/dns_resolve.bend     # DNS fast paths + fail-closed host checks
examples/{wsm,wss,httpx,real}/  # runnable interop programs, by lane (not published)
docs/site/                # this library's own site (httpx_site serves it)
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

Hub import (after a publish, see below). Imports are not transitive. The
entry only marks the bundle, so import the API from its own file:

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

Requests and responses are tuples. A request is
`method & path & headers & body`; a response is
`status & headers & body`. Headers are `List<&1, String & String>`.

Binary socket effects (`lib/tcp.bend`, import as `TCP`) — the byte-level
twin of Base's `TCP.send`/`TCP.recv`, so frames never go through UTF-8:

| Function | Description |
|---|---|
| `send_bytes` | Send a `List<&2, U32>` (0–255); a value past 255 fails with `EINVAL` before any byte leaves; `EAGAIN` parks on `POLLOUT` |
| `recv_bytes` | Receive at most `max` bytes as `List<&2, U32>`; parks on `POLLIN` |
| `recv_frame` | Isolate exactly one WebSocket frame, seeded by `buf` (the previous rest); answers the frame plus every byte read past it, so no byte is lost. A total past `max` is `Fail 413`, a partial EOF `Fail 400 "eof"` |

All three hand the socket back as
`Socket & Result<&1, &1, U32 & String, …>` on every path.

## DNS

`lib/dns.bend` (import as `DNS`) resolves a host to one IPv4 dotted
quad, package-locally
(`resolve(host) -> IO(Result<&1, &1, U32 & String, String>)`). Canonical
dotted quads and `localhost` answer without the effect. Every other host
must pass the host checks (printable ASCII, 253 bytes at most, dot-labels
1–63), or it fails with `Fail 601`.

Fail codes are stable numbers, never resolver text:

- `601` bad host
- `602` host not found
- `603` resolve failed (try again)
- `604` no IPv4 address
- `605` resolve error

The C twin uses `getaddrinfo` on a helper thread. It maps the EAI
verdicts onto that table: `602` EAI_NONAME, `603` EAI_AGAIN, `604` no
AF_INET answer, `605` the rest.

The JS twin writes one A query over UDP to the first IPv4 nameserver of
`/etc/resolv.conf`. It reads that file with the runtime's own guarded
`fs` (the last `dlopen` in the resolver is gone, 2026-10-12). It skips
IPv6 entries and falls back to `127.0.0.53` when the file lists none. It
parks on the socket with a 3 s deadline and retries once on silence
(`603` on the second). Then it answers the first A record: `602` on
NXDOMAIN, `603` on SERVFAIL, `604` when the answer carries no A record,
`605` otherwise.

`tests/effs/parity.sh` pins the twins to the twin rules. The golden
`tests/io/dns_resolve.bend` pins the pure fast paths and the `601` checks
only. The effect codes `602`–`605` are table-driven in the twins. The
manual real-host example exercises them, not a golden.

`fetch` and `send_request` connect by the resolved IP, but they send the
ORIGINAL host in `Host`. Virtual hosting never changes.

A host that is an address form but not a canonical dotted quad
(`256.1.1.1`, `01.2.3.4`, `127.1`, `0x7f.1`) fails `601` in the pure
layer. This failure occurs before the effect, on both lanes. libc reads
those as IPs (`01.2.3.4` → `1.2.3.4`, `127.1` → `127.0.0.1`), so the
guard keeps the lanes equal. `tests/io/dns_resolve.bend` pins the four
cases.

## TLS

`lib/tls.bend` (import as `TLS`) is a client and server TLS lane over the
byte effects. It has **one public contract and two wire implementations**
(how and why: `docs/tls-dns.md`):

| Twin | What it is |
|---|---|
| C (`lib/effs/tls_*.c`) | OpenSSL through `dlopen` for the native binary target; the handshake runs on a blocking fd in the helper thread (`O_NONBLOCK` restored on the success path; every failure path closes the fd instead) |
| JS (`lib/effs/tls_*.js` + `tls_rt.js`) | TLS 1.3 + 1.2 in pure JS over the host's `crypto` builtins (AEAD aes-128/256-gcm + chacha20-poly1305, ECDHE), no `bun:ffi`, no libssl; parks on `WANT_READ`/`WANT_WRITE` |

**The dial is Base's, the handshake is the effect's** (since 2026-10-13,
commit `1f74cc9b`). `tls_connect_raw` receives an *already-connected* fd
from `Base.TCP.connect` and only handshakes it. `Base.TCP.connect` puts a
real fd in `op.args[0]`, the only thing `io_park_on` can wake on. The
composition lives in Bend (`DNS.resolve` → `TCP.connect` → handshake), so
a dial has one owner. DNS failures keep the 601-605 codes before any
socket exists.

| Function | Description |
|---|---|
| `tls_connect(host, port)` | Resolve (DNS), connect and handshake with chain verification; SNI is the ORIGINAL host; ALPN `h2` is required |
| `tls_connect_insecure(host, port)` | Same handshake without chain verification (loopback/self-signed tests) |
| `tls_connect_noalpn(host, port)` / `tls_connect_noalpn_insecure` | Same without offering ALPN (WSS / HTTP/1.1 Upgrade over TLS) |
| `tls_connect_any(host, port)` / `tls_connect_any_insecure` | The dual client: offers `h2` + `http/1.1` and hands back the socket with the selected protocol (the entry the HTTPS facades use) |
| `tls_accept(listener, cert, key)` | Accept one TCP connection and handshake it with the PEM cert/key files; ALPN `h2` is selected when the client offers it, and a client that offers nothing completes with no protocol selected (RFC 7301 §3.2) |
| `tls_accept_alpn(listener, cert, key)` | The dual server: `h2` or `http/1.1`, whichever the client offers first |
| `tls_accept_http1(listener, cert, key)` | The `http/1.1`-only server (the WSS/Upgrade peer) |
| `tls_send_bytes` / `tls_recv_bytes` | Byte-faithful send/recv (List<&2, U32>) over the TLS socket; WANT_READ/WANT_WRITE parks (`max` is floored at 1; only the C lane also clamps it at `INT32_MAX`) |
| `tls_close` | Orderly shutdown (close_notify), session free, fd close |

Fail codes are stable numbers:

- `611` bad input (port/fd/ALPN shape; the C lane also rejects a
  NUL-bearing host)
- `612` dial failed — with the transport since the dial left the effect
  (the dial answers `TCP.connect`'s own errno; `612` stays a family
  number)
- `613` handshake failed
- `614` verify failed (chain, the validity window of every certificate,
  hostname)
- `615` ALPN mismatch
- `616` TLS error

`615` is a verdict of both roles and both lanes. A peer whose offered list
has no overlap is refused with the fatal no_application_protocol alert
(RFC 7301 §3.2). The effects classify it by the OpenSSL reason code: 235
when we refused, 1120 when the alert arrived. Thus
`bend tests/io/tls_alpn_none.bend` prints `1111` on the interp/JS lane and
on a `bend -o` binary alike. A peer that offers no ALPN at all is not a
mismatch: the handshake completes with no protocol selected.

The TLS handle is opaque (a session/pump box, never a raw fd): close it
with `TLS.tls_close`, not `Socket.close`. DNS failures keep the 601-605
codes and happen before any socket exists.

The lab under `tests/effs/` proves the two lanes. It has the twin lint
(`parity.sh`), the interop ladder against system OpenSSL in Node AND Bun,
and the golden `tls_alpn_none.bend`. That golden drives the effects
through the real runtime. In the ladder (`tls-generic.sh`),
`BEND_EFFS_DIR=lib/effs` runs the same rungs against the installed files.
Only the hermetic `cbc-len` rungs peer with Node's own `tls`, because the
bun TLS code refuses the cipher:

```sh
bend tests/io/tls_connect_close.bend   # 111
bend tests/io/tls_alpn_dual.bend       # 1
bend tests/io/tls_alpn_none.bend       # 1111
bash tests/effs/parity.sh              # 26 passed, 0 failed, 3 known
bash tests/effs/eff-unit.sh            # 2 passed, 0 failed (hermetic twin units: DNS codes, recv clamp)
```

## HTTP/2

`lib/http2.bend` (import as `H2`) is a native HTTP/2 (RFC 7540/7541)
client and server on the TLS lane. Frames and HPACK are pure Bend, with
no nghttp2/node:http2:

| Function | Description |
|---|---|
| `h2_connect(host, port)` / `h2_connect_insecure` | TLS dial, magic preface + SETTINGS |
| `h2_request(sock, sid, method, path, headers, body)` | One request/response exchange on stream `sid` (1, 3, 5, ...); the socket and next sid thread back |
| `h2_serve_once(sock, handler)` | Serve one request stream: preface, SETTINGS, HEADERS/DATA → `handler(H2Request) -> IO(H2Response)` → response frames |
| `h2_serve_next(sock, handler)` | Serve one more stream on an established connection (no preface); thread for sequential keep-alive (sid 1, 3, 5, ...) without a new handshake |

HPACK decodes the full RFC 7541 subset. It reads literal (all three
modes), static-table indexed (1–61) and dynamic-table indexed references,
and huffman strings (canonical Appendix B code). It accepts dynamic-table
inserts with eviction (entry = len + len + 32, max 4096) and table-size
updates.

Integer continuations past 5 bytes fail closed with `502` (RFC 7541 §7.4
implementation limit). The encoder stays literal without huffman. That
output is valid HPACK every peer decodes, so Bend→Node needs no huffman
encoder. Header blocks that split across CONTINUATION, and frames over
16384, still fail closed (`400`/`413`, backlog).

`examples/real/httpx_real.bend` is a manual smoke against live hosts.
Observed 2026-09-28: example.com GET/POST OK, cloudflare.com `fetch` OK
on ~1.3 MB, info.cern.ch OK through H1. It is never part of the gate.

Multi-stream keep-alive clients against huffman peers stay on single-shot
`request` (fresh table per connection, always correct). Per-connection
decode state threads through the server loops and the concurrent mux.

```sh
bend tests/io/h2_loopback.bend         # 1
```

## HTTPS

`lib/https.bend` (import as `HTTPS`) is the public HTTPS facade over
TLS + DNS + the HTTP/2 codec. It gives request/response/fetch and generic
keep-alive servers, like `lib/http.bend`:

| Function | Description |
|---|---|
| `request(host, port, method, path, hs, body)` / `request_insecure` | Single-shot exchange on stream 1 (connect + request + close); answers the full `H2Response` (status + headers + byte body) |
| `send_request(host, port, path, method, hs, body)` / `send_request_insecure` | Same exchange with a `String` body; answers the response body as `String` |
| `fetch(url)` / `fetch_insecure` | `https://` GET by URL (with `HTTP.read_url`); `http://` refused with `Fail 400`; answers the body as `String` |
| `fetch_bytes(url)` / `fetch_bytes_insecure` | Same GET answering raw `List<&2, U32>` bytes |
| `server_on(~H, l, cert, key)` | Generic keep-alive server (like `HTTP.server_on`): unbounded TLS accept loop with `IO.spawn` per connection, unlimited sequential streams per connection until GOAWAY/EOF; `~H` is `H2Request -> IO(H2Response)` |
| `server_on_concurrent(~H, l, cert, key)` | Same accept loop; per connection an unbounded interleaved mux (open streams tracked in a `List<H2SrvSt>` by sid, answered in any completion order; header fragments parked until CONTINUATION completes the block) |
| `server_on_alpn(~H2, ~H1, l, cert, key)` | Same, but ALPN splits the port: `h2` to the H2 codec, `http/1.1` to `lib/https_http1.bend` (same `IO.spawn` per connection) |
| `server_on_concurrent_alpn(~H2, ~H1, l, cert, key)` | ALPN split + unbounded interleaved mux |
| `mux_start(~H, sock)` | One-shot concurrent serve on an established TLS socket (the test entry of the mux) |
| `server_on_http1(~H, l, cert, key)` | HTTP/1.1-only server (the module of `lib/https_http1.bend`, ALPN `http/1.1` only) |

Bodies are byte-faithful `List<&2, U32>` at the core (`encode_body` /
`decode_body` wrap `H2.str_bytes` / `H2.bytes_str`). Headers are
`List<H2Hdr>` (`pairs_to_h2` / `h2_to_pairs` convert http-style pairs).
Fail codes surface unchanged: `400/413/502/503` (codec), `601-605` (DNS),
`611-616` (TLS).

**Contract (2026-09-25, task-020):**

- `server_on` has **no fuel**: one accept loop serves streams until
  GOAWAY/EOF, the same contract `node:http2` expects.
- The client offers `h2` **and** `http/1.1` (ALPN mode 2) and speaks
  whichever the server picks; a peer without ALPN gets HTTP/1.1. The H1
  lane lives in `lib/https_http1.bend`. It uses the pure codec of
  `lib/http.bend` again, with TLS as the only transport change, and
  answers byte-faithful (chunked and binary included).
- The server side splits on ALPN too: `tls_accept` is strict `h2`
  (legacy contract), `tls_accept_alpn` is dual, `tls_accept_http1` is
  H1-only.
- Flow control: the codec announces `INITIAL_WINDOW_SIZE=6 MB` and
  `MAX_FRAME_SIZE=65535`. It replenishes the connection and stream
  windows on every inbound DATA, and it slices uploads into
  `WINDOW_UPDATE`-paced frames. Bodies are not capped at 64 KB.
- Header blocks survive `CONTINUATION` in both directions, and they
  carry a per-response HPACK dynamic table on the client. The 64-header
  fuel cap is gone (`512` fields, `512` HPACK tokens).
- `RST_STREAM`, `GOAWAY`, `PING` and `WINDOW_UPDATE` are handled as
  protocol events, not as skips. Housekeeping frames are answered with a
  fresh-only `ACK` (never an ACK-of-an-ACK, which ping-pongs between two
  unbounded read loops).
- The frame reader has no read budget: it reads until a whole frame
  lands. A peer that splits a frame over many TLS records (public sites
  deliver ~1.4 KB per record) no longer answers `400 eof`.

```sh
bend tests/io/httpx_fetch_https.bend   # 1
bend tests/io/httpx_streams.bend       # 1
bend tests/io/httpx_server_on.bend     # 1
bend tests/io/httpx_mux.bend           # 1
bend tests/io/httpx_http1_module.bend  # 1
bend tests/io/tls_alpn_dual.bend      # 1
bend tests/io/h2_frame_read.bend      # 8
bend examples/real/httpx_real.bend    # manual live smoke
```

## HTTPX (isolation)

`lib/httpx.bend` (import as `HTTPX`) is a standalone server + client with
a mini-H2 codec inside. It imports `Base` + `tls` only, never
`http2`/`https`. It exists to isolate overhead (no Huffman rebuild per
probe on the hot path, no per-hop dynamic table, no flow-credit sends on
the server). The `## HTTPS` contract above is unchanged and keeps the
full codec. Architecture (the two delivery modes, why streaming handlers
are pure): `docs/modes.md`.

| Function | Description |
|---|---|
| `server.on(~H, l, cert, key)` / `server.on_alpn` | Sequential generic server (one stream at a time; pipelined HEADERS gets `RST_STREAM` 7) / ALPN split with one handler for both lanes |
| `server.on_h2(~H, l, cert, key)` / `server.on_h1(~H, l, cert, key)` | Mono-protocol forks: H2-only / H1-only (H1 lane is a local port of `http.bend` shapes: `Content-Length` **and** `Transfer-Encoding: chunked` framing, **keep-alive** — the server answers and reads the next request on the same connection until `connection: close`, EOF or a terminal 413/502) |
| `server.on_h1_plain(~H, l)` / `server.echo_h1_plain(l)` | The same keep-alive H1 server over plain TCP (`TCP.listen`/`accept`), no cert/key — the `http://` peer |
| `server.once(~H, l, cert, key)` / `server.once_h1(~H, l, cert, key)` | Accepts **one** connection and stops (no recursion) — the entry a test or single-shot server wants; `once_h1` is the `http/1.1` pair |
| `server.echo(l, cert, key)` / `server.echo_alpn` | The fixed echo server: status 200, no headers, the request body back (`echo_body`) |
| `server.concurrent(~H, l, cert, key)` / `server.concurrent_alpn` | Interleaved httpx echoing `Request -> IO(Response)` (slots by sid, any completion order; `_alpn` is H2-only, non-H2 closes — use `server.on_alpn` for the H1 split) |
| `server.stream(~H, l, cert, key)` / `server.stream_alpn` | Upload streaming with `SrvReqHead`/`SrvReqData` events to a pure `~H`: `Continue` buffers, `RespondEarly` answers without draining, `Cancel` resets that stream with `RST_STREAM` 8 and the siblings continue. `stream_alpn` dispatches H2/HTTP-1.1 by ALPN (`server.stream` stays H2-only behind `tls_accept`); `server.stream_plain(~H, l)` is the plaintext `http://` peer (one request per connection, then close) |
| `server.stream_concurrent(~H, l, cert, key)` / `server.stream_concurrent_alpn` | The same contract with the H2 interleave loop: several uploads stay open on one connection, and each event carries its slot (2026-10-16, task-054). The `_alpn` variant adds the H1 leg on the same port; H1 has no multiplexing, so each connection serves one request. `server.stream_concurrent_plain(~H, l)` is the plaintext `http://` alias of `server.stream_plain`, which is the same loop |
| `client.once(_insecure)(host, port, Request)` | One-shot: dial + one `client.request` + close. `client.request` dispatches both ALPN answers, so the H1 leg needs nothing of its own |
| `client.on(_insecure)(host, port, reqs)` | Sequential batch entry: one dial, N requests, answers in order; first `Fail` aborts. H2 keeps sids 1, 3, 5, ... and the HPACK table; an `http/1.1` connection reuses the one socket through the H1 lane (`client_seq.h1`) |
| `client.echo(_insecure)(host, port, path)` | A disposable `GET` over `client.once` |
| `client.connect(_insecure)(host, port)` | Hands back `Socket & CliSt{sid, tab, is_h2}`. `client.request(sock, st, host, port, req)` is **one** exchange on it, both ALPN answers, and it **never closes**: the caller closes (`client.on`/`client.once` do) or calls again for the next request, threading the socket and the state — the returned `CliSt` carries the advanced sid and the HPACK table the next response decodes against. N requests are that loop at the call site |
| `client.concurrent(_insecure)(~H, host, port, reqs)` | Pipelined N requests (sids 1, 3, 5, 7, ...) drained through slots, scored by `~H: Response -> U32` |
| `client.stream(_insecure)(~H, host, port, ...)` | Download streaming with a pure `~H` (`StreamHead`/`StreamData`); dispatches H2/HTTP-1.1 by ALPN on the one socket. `StreamCancel` sends `RST_STREAM` on H2, closes with `Fail` 8 on H1. `client.stream_plain` is the plaintext `http://` peer |
| `client.stream_concurrent(_insecure)(~H, host, port, reqs)` | Pipelined N requests on one H2 connection, streamed to a pure `~H: CStreamEv -> CStreamOut`: each event and each answer carries the stream slot, so `CStreamCancel{slot}` resets that stream (`RST_STREAM` 8) and the siblings continue. The answer is `(total bytes, finished streams)`, and a cancel is not counted (2026-10-16, task-054) |
| `client.stream_concurrent_plain(~H, host, port, reqs)` | The plaintext `http://` peer of the row above: one connection for each request through `client.stream_plain`, with all dials in flight at the same time. H1 has no multiplexing, and a template handler cannot capture a runtime slot, so this entry keeps `~H: StreamEv -> StreamOut` and the answer counts the finished connections (task-054) |
| `request(_insecure)` | Any method with headers and a `String` body over `client.once`; answers the response body as `String` |
| `request_bytes(_insecure)` | Same with raw-bytes body in and out |
| `fetch(_insecure)` / `fetch_bytes(_insecure)` | GET by URL over `read_url` (ported from `http.bend`, no import); `http://` is served by `_insecure` over the plaintext H1 lane, and refused `400` when verifying |
| `h1_once(_insecure)` | Single-shot over the H1 lane (no-ALPN dial, WSS-style) |

Surface (TASK-036, kept different by decision): the `lib/core` +
`lib/utils` toolkit (`str_bytes`, `len`, `take`, `valid_host`, `code_*`,
and more) stays in the tree. It has zero production callers, and HTTPX
already owns the equivalents internally (`x_*`, `client.on.valid_*`).
Only `read_url` is top-level here.

Retired text lane (TASK-036 phase 7): the 4-String handler shape
(`serve_once(sock, handler)`, `echo.body`/`echo.serve`, the 25
`h1_pair_*` names) is gone on purpose. Its two live callers
(`httpx_h1_fetch`, `httpx_h1_fetch_host`) now speak `Hdr` /
`Request -> IO(Response)` over `server.on_h1_plain`. Its
`501 "tls missing"` for https URLs retires with it (HTTPX answers `400` /
dial failure).

Limits (fail-closed, by design):

- Responses are literal-only, and DATA is sliced to conn+stream windows
  (pump v2, no 16 KB cap).
- `WINDOW_UPDATE` credit flows both directions (server per DATA,
  streaming-download client per non-final DATA, else >64 KB stalls).
- Fragmented header blocks (CONTINUATION) reassemble inline-blocking on
  all three client drains and on `httpx_stream` (RFC 9113 §6.10 forbids
  interleave mid-sequence, so no per-stream ledger).
- Huffman/dynamic-table peers decode (static 1–61, literal, Huffman
  strings, minimal dyn table), which is what `node:http2` needs.
- H1 headers are checked at render time. A CR/LF/NUL in a name or a value
  is refused (`Fail` 400 on a request, a bare 500 on a response). The
  field does not end early, and the rest does not ship as headers nobody
  asked for.

The H1 lane decodes `Transfer-Encoding: chunked` in **both** directions
(TASK-033). One step machine (`x_h1.chunk_step`, ported from
`lib/web/http/main.bend`'s `h1_chunk_step`) feeds the client body reader
and the two server request readers. Bodies are copied in blocks instead
of byte by byte. The caps are the lane's own: client fuel (413
`response too long`), server fuel (413 `request too long`) and the
server's 16384-byte body cap (413). A truncated chunk, a non-hex size, a
trailer section and bytes after the terminator are all `400`. The server
answers `bad chunked`; a peer that closes mid-body gets `eof`. A partial
body is never read as a whole one.

A hex size that does not fit the U32 counter has no explicit guard, the
same as the reference machine. That size cannot become a silently wrong
body. The measured vector answers `400`, because a wrapped size no longer
matches the bytes that follow it.

H1 server head rules (TASK-042 phase 6): the H1 server refuses with
`400`, before it reads a single body byte, a head it cannot frame:

- a `Transfer-Encoding` next to a `Content-Length` (the request-smuggling
  pair: a proxy in front may pick the other framing and the two peers
  disagree on where the body ends)
- a `Transfer-Encoding` that is not `chunked` (RFC 9112 §6.3: the body
  length cannot be determined)
- two `Content-Length` fields
- a `Content-Length` that is not a plain decimal (`-1`, `5x` and an empty
  value all read as 0 through `U32.read`)
- a missing `Host` on an HTTP/1.1 request
- a duplicated or empty `Host` (RFC 9112 §3.2; a 1.0 request may omit it
  and is still served)

One validator serves the three server lanes: keep-alive
(`on_h1`/`on_h1_plain`/`once_h1`), the 101 upgrade lane
(`on_h1_open_plain`/`once_h1_open`) and the streaming lane
(`stream_plain`).

A head past **16384 bytes** is `431 Request Header Fields Too Large`.
That number is the one `lib/http.bend` documents for its lane and the
default of `node --max-http-header-size`. The read fuel is only the
slow-drip backstop. Every terminal failure whose code is `400..599` is
**rendered as a response before the connection ends**. TASK-033 set that
rule for the chunk reader. The `(0, "close")` and the `6xx` transport
codes stay silent closes instead. `tests/io/httpx_h1_hardening.bend`
measures all of it on the wire, one raw connection per case.

H2 control errors (TASK-042 phase 5): a `GOAWAY` or an `RST_STREAM` is a
typed stream error, never a bare `502`. The fail code carries the RFC
9113 §8.7 verdict. The code is `503` when the peer said the stream was
**not processed**: a `GOAWAY` above the stream id, or an `RST_STREAM`
`REFUSED_STREAM`. Then the caller may repeat the request. The code is
`502` when the peer may have processed it. The text names the wired code
and the last-stream-id (`goaway NO_ERROR(0) last=1 sid=1`). A `GOAWAY`
shorter than the 8 bytes of §6.8 fails closed as `FRAME_SIZE_ERROR`. The
three client drains and the flow sender all use it.

A **sibling's `RST_STREAM`** is not ours to fail on: `node:http2` resets a
stream it already answered while the next request's body is still coming.
The single-stream drains filter it by sid and the sender stashes it into
the read seed, so the drain decides. `tests/io/httpx_h2_goaway.bend`
covers the six shapes.

Streaming contract (TASK-036, kept different by decision): the download
family is `StreamEv{StreamHead, StreamData}` /
`StreamOut{StreamContinue, StreamCancel}`. The upload family is
`SrvEv{SrvReqHead, SrvReqData}` / `SrvOut{Continue, RespondEarly,
Cancel}`. The concurrent client family is `CStreamEv{CStreamHead,
CStreamData}` / `CStreamOut{CStreamContinue{slot}, CStreamCancel{slot}}`
(task-054): the slot names the stream, so one pure handler serves several
streams of one H2 connection.

`lib/core/type.bend` speaks one 3+3 family,
`CT.StreamEv{StreamReq, StreamHead, StreamData}` /
`CT.StreamOut{Continue, RespondEarly, Cancel}` with
`frame: Maybe<BodyFrame>`. The families are **not interchangeable**: a `~H`
written against one does not compile against another. H1 carries no slot,
and a template handler cannot capture one (task-054 C13), so
`client.stream_concurrent_plain` keeps `StreamEv`.

Streaming in HTTPX speaks both lanes (TASK-036 phase 6). `client.stream`
and `server.stream_alpn` dispatch H2/HTTP-1.1 by ALPN on the negotiated
socket. `server.stream` stays H2-only behind `tls_accept`, which requires
h2 at the handshake; `client.concurrent` stays H2-only behind `h2_only`.
`client.stream_plain` / `server.stream_plain` are the plaintext `http://`
peers. The H1 lanes are one request per connection, then close. They have
no keep-alive and no pipelining. The concurrent plaintext entry opens one
connection for each request, so N requests travel at the same time.
Backpressure is the read itself (at most one recv per chunk). `x_h1.frame_of` threads the framing decision through
the download lane. The upload lane frames from the request head the same
way the one-shot H1 server does.

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
bend tests/io/httpx_stream_concurrent.bend # 4 (cancel resets one stream, siblings continue)
bend tests/io/httpx_client_stream_concurrent.bend # 3 (client slots: cancel one, siblings finish)
bend tests/io/httpx_client_stream_concurrent_skip.bend # 1 (frames in flight of a dropped stream)
bend tests/io/httpx_client_stream_concurrent_plain.bend # 5 (N clear H1 connections at once, alias server)
bend tests/io/httpx_read_url.bend         # 1 (pure URL vectors)
bend tests/io/httpx_fetch.bend            # 1 (fetch by URL vs mini server)
bend tests/io/httpx_client_seq.bend       # 3 (batch entry vs mini server)
bend tests/io/httpx_server_seq.bend       # 2 (terminal requests vs sequential server)
bend tests/io/httpx_http1_fallback.bend   # 1 (dual client vs H1 server)
bend tests/io/httpx_server_alpn.bend      # 2 (ALPN split, H2 + H1 clients)
bend tests/io/httpx_echo_once.bend        # 2 (server.once + server.echo, client.once/echo)
bend tests/io/httpx_plain_h1.bend         # 4 (http:// end to end over server.on_h1_plain; four requests)
bend tests/io/httpx_h1_keepalive.bend     # 14 (H1 close policy + reuse + client batch + terminal)
bend tests/io/httpx_flow.bend             # 1 (25 KB up+down through pump v2 + WU credit)
bend tests/io/httpx_client_cont.bend      # 1 (fragmented HEADERS+CONT vs once drain)
bend tests/io/httpx_client_cont_stream.bend # 1 (same peer vs streaming drain, no double-Head)
bend tests/io/httpx_client_cont_conc.bend # 1 (same peer vs concurrent drain)
bend tests/io/httpx_concurrent_cont.bend  # 1 (fragmented HEADERS+CONT vs httpx loop)
bend tests/io/httpx_server_cont.bend      # 1 (fragmented HEADERS+CONT vs httpx_stream)
bend tests/io/httpx_request.bend     # 2 (String + bytes bodies vs mini server)
bend tests/io/httpx_site.bend         # 5 (docs/site/: 3 routes + 2 handler vectors)
bend tests/io/httpx_got_contra.bend   # 52 (got contra-proof: split arms, projections, taken)
```

### `got`: one match, every projection

A *projection* def is a thin `get`: it matches its parameter once and
answers one field (`x_resp.rh`, `x_resp.ok`, `x_resp.tab`). A `got`
answers every field of that one match instead. Form A,
`E -> P1 & P2 & ...`, is live in three places. `x_req.got` answers head,
ok and table; `x_tab.lookup.got` fuses the bounds check with the fetch;
`x_h1.frame_of` gives `cl_of`, `is_chunked` and `no_body` in one pass.
Form B, `E -> E & P`, hands the structure back together with the
projection for a caller that needs both.

Validity window, measured in this tree (probes in `.scratch/gotprobe/`):
a **computed** pair cannot be scrutinized. The form `(a, b) = src()` is
refused with "a match cannot scrutinize a computed value". The same pair
**as a parameter** destructures normally. So the only door into a `got`
answer is a consumer that takes it as its own parameter.

`+` (dup) covers `Data` records and Base's `List`/`String`. A bare pair
`A & B` is neither. A pair that must outlive two uses is wrapped in a
`Data` record (`Taken`, `FendTaken`), or it is re-derived. When a `got`
pays, measure the matches and traversals it saves against the `get` plus
`+` it replaces. `test.bend` has the shapes: a pair costs nothing next to
a rebuild. A U32 counter beats a `Nat` one, while a list walk dominates.

### Closed / ignored by design

What HTTPX does **not** do, and why — so a missing behavior is not read as
a bug (TASK-042, phase 7):

| Item | Why it is out |
|---|---|
| `h2c` (H2 over plaintext, prior knowledge or `Upgrade`) | a browser never speaks it: it takes `h2` from ALPN over TLS. Plaintext stays on the H1 lane (`server.on_h1_plain`, `client.fetch_insecure`). Making it work is a task of its own |
| IPv6 / `AAAA` | the dial resolves `A` records only (`lib/dns.bend`). A browser that resolves `localhost` to `::1` falls back to `127.0.0.1` through Happy Eyeballs, so the peer still connects |
| Trailers handed to the handler | no trailer event exists in `StreamEv`/`SrvEv`, and one more event changes the public contract. A trailer block is recognized, closes the body and never replaces the response head (RFC 9113 §8.1) |
| `server.on` (sequential) with N parallel browser fetches | one stream at a time by design: a pipelined `HEADERS` gets `RST_STREAM 7` (documented in `docs/modes.md`). A browser with parallel fetches wants `server.concurrent` |
| `PUSH_PROMISE` | the client has no push handler and never answers one; a promise is stashed by the sender or skipped by the drain. It is not an error, just not a feature |
| Huffman **encoding** | the encoder stays literal (valid HPACK, only bigger); the decoder covers huffman, static 1–61, literals and a minimal dynamic table — which is what `node:http2` needs |
| `client.concurrent` over HTTP/1.1 | H2-only by design (`h2_only` closes an H1 connection with `615`); the H1 lane has `client.on` and `client.stream` |

## WebSocket (WSM)

`lib/wsm.bend` (import as `WSM`) is **one** RFC 6455 implementation for
both schemes. The handshake rides the H1 upgrade lane of `lib/httpx.bend`
(the `101` detaches the socket: `h1_open` on the client, `on_h1_open` on
the server). The frames ride `lib/tls.bend` / `lib/tcp.bend` directly
once the socket is handed over. Nothing in the module imports `ws.bend`,
`wss.bend` or `http.bend`: the codec (frames, mask, close, ping/pong,
fragments, UTF-8) and the handshake live in the module. `lib/ws.bend` and
`lib/wss.bend` are **superseded**. They stay for old callers only. The
whole loop, handshake and split existed twice there (once over `TCP.*`,
once over `TLS.*`), which is the cost this module removes.

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
by name, not by a flag. The same holds for verification on the client:
the `_insecure` suffix is the only way to skip it. `~H` is the same
handler in both lanes: `WSEv -> IO(WSOut)`, one step per frame, one
`EvOpen` after the handshake.

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

Messages and events: `WSMessage` is `WSText{text}` or `WSBin{data}`.
`WSOut` is `OutMsg` / `OutOp` / `OutRaw`. `WSIn` is `InMsg` / `InOp`.
`WSEv` is the lifecycle event (`EvOpen`, `EvMsg`, `EvPing`, `EvPong`,
`EvClose`, `EvError`). `WsStep` and `MsgAcc` are loop internals, and
`WSMask` is the client key. The names mirror `lib/websocket/type.bend`,
so the move between the two trees is a requalification, not a redesign.

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

**Close state (2026-09-25, task-020):** the close handshake is complete.
An empty close payload reports `1005` to the application but never puts
`1005` on the wire (the echo of an empty close used to make Node answer
`1002`). A 2-byte payload is validated (2 bytes, known code, UTF-8
reason, `1005/1006/1015` refused). Text frames and close reasons are
validated as UTF-8, so a peer answers `1007` instead of a silent
acceptance of replacement characters. Fragments are reassembled (`1/2`
then `0*` until `FIN=1`) in both directions. The payload cap (`16 MB`)
answers `close 1009` instead of a bare TCP close.

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

bend examples/wss/wsm_binance_bookticker.bend | head   # live public peer
```

## Helpers

| Module | Function | Description |
|---|---|---|
| `lib/sha1.bend` (`SHA1`) | `sha1(bytes)` | FIPS 180-4 digest of a byte list |
| `lib/b64.bend` (`B64`) | `encode(bytes)` / `decode(string)` | base64 over byte lists |
| `lib/static.bend` (`Static`) | `read_bytes(root, path, cap)` | Read a file under `root` as raw `List<&2, U32>`; `400` bad path, `404` missing, `413` when it does not fit `cap` — never a truncated body |
| | `safe_read(root, path)` | The same read as `String`, capped at `TEXT_CAP` (8 KB) with the same codes |
| | `content_type(path)` | Content-Type from the file extension |

## Examples

`examples/` holds runnable programs that are not part of the package,
grouped by lane. `wsm/` has the `ws://` session: five server/client pairs,
Bend and Node, hand-driven and event-driven. `wss/` has the `wss://`
peers plus the saturate driver and the live probe. `httpx/` has the
`lib/httpx.bend` peers: mini-H2, ALPN split, the H1 lanes and the site
launcher. `real/` has live public hosts, by name. `examples/README.md`
indexes every pair with its port and command; the gate only typechecks
them (`check.sh --checks`).

`real/https_real.js` is the HTTPS smoke (manual; example.com OK,
cloudflare.com plain `fetch` on ~1.3 MB, info.cern.ch through H1 — it may
still `Fail` closed on other peers: HPACK subset / CONTINUATION).
`wss/wsm_saturate.bend` is the manual load driver (20 parallel clients
per lane over ephemeral ports; prints `SAT`/`BENCH` lines), and it never
runs in the gate. `wss/wsm_binance_bookticker.bend` is the live
public-peer probe. It dials `wss://stream.binance.com:9443/ws` with
`client_on` (real TLS, cert verified) and sends one `SUBSCRIBE` frame for
`bnbusdt@bookTicker`. It prints a `BOOK` line per update (symbol, best
bid/ask price and size) until the 15 s sleep in `main` halts the run.
Pipe it through `head`.

HTTPX interop (`lib/httpx.bend`, manual only, never in the gate):
`httpx/httpx_echoserv.bend` serves the mini-H2 echo on an ephemeral port
(printed to stdout; binary builds in <45s).
`httpx/httpx_server_stream.bend` serves the streaming-upload cap-3 handler
on an ephemeral port. `httpx/httpx_client_once.bend` dials a node echo
server (`httpx/mux_node_echoserv.js 19893 1`) with `client.once_insecure`
and checks status 200 + echo. `httpx/mux_node_client.js [port] [n]` fires
N concurrent POSTs on one `node:http2` session (`DONE n/2N+2`).
`httpx/mux_node_echoserv.js [port] [n]` is the H2-only echo for Bend
clients. `httpx/mux_node_bigserv.js [port] [n]` answers 100 KB for
streaming-download clients. Measured 2026-09-27: N=20 `DONE 42/42` under
node and bun against the C binary server.
`real/httpx_client_once_bulk.bend` GETs the live Binance `exchangeInfo`
feed (~5.8 MB JSON) with `client.once` and prints status + length + head.
Measured 2026-09-28: `STATUS 200 LEN 5851449 DONE 3/3` (build the C binary
first, interp is too slow for multi-MB bodies).
`real/httpx_fetch_bulk.bend` GETs the same feed with `fetch_bytes` and
prints length + head. Measured 2026-09-28: `LEN 5851449 DONE 2/2`.

`httpx/httpx_site.bend` is the library's own site: it serves `docs/site/`
on `http://127.0.0.1:8080/` (plain H1 keep-alive) and on
`https://127.0.0.1:8443/` (ALPN split, h2 + http/1.1, test PEMs). It
reads the files per request with `Static.read_bytes`. It is the runnable
counterpart of `tests/io/httpx_site.bend`.

Every WS peer runs the same scripted 6-step session on `127.0.0.1:19880`
(`/chat`): `101 -> ping s1/pong -> ping c1/pong -> hello/echo ->
ping s2/pong -> close`. Run one server at a time from the repo root.
Each side prints one `OK` line per step and `DONE 6/6` (pass = `DONE`
present with no `FAIL`).

```sh
bend examples/wsm/server.bend     # then: bend examples/wsm/cliente.bend
bend examples/wsm/server_on.bend  # then: bend examples/wsm/cliente_on.bend
# ws peers need `ws` resolvable under node (bun uses its builtin):
NODE_PATH=/tmp/wsport/node_modules node examples/wsm/server.js 19880
NODE_PATH=/tmp/wsport/node_modules node examples/wsm/client.js 19880
bun examples/wsm/server.js 19880       # all four ws peers run under bun
node examples/wsm/server_native.js 19880   # no dependencies (also bun)
node examples/wsm/client_native.js 19880   # no dependencies (also bun)
```

Any server talks to any client (`wsm/server.bend <-> wsm/client.js`,
`wsm/cliente.bend <-> wsm/server.js`, `wsm/server_on.bend <->
wsm/client_native.js`, `wsm/cliente_on.bend <-> wsm/server_native.js`,
and more pairs). `check.sh --checks` typechecks the `.bend` files and
syntax-checks the `.js` files. `http_real.bend` is a manual smoke test of
live sites BY NAME (it needs a working resolver), and it never runs in
the gate.

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
- `fetch` reads at most 8 × 8192 bytes (64 KB cap), then truncates. The
  HTTPS lane (`lib/https.bend`) has no such cap: it streams with HTTP/2
  flow control and a 16 MB WebSocket payload cap.
- Client WebSocket frames are masked with a key drawn from the host
  entropy pool (`IO.random_u32` → `getrandom`/`arc4random`, RFC 6455
  §5.3). `show_masked(fin, op, payload, k0..k3)` stays public for tests
  that want a fixed key on purpose; no production path uses it.
- Name hosts resolve with `lib/dns.bend` (fail-closed, `Fail 601`–`605`);
  the resolved IP is transport-only — `Host` keeps the original name.
- TLS verifies the chain and the hostname against the root store the host
  ships. The C lane rides `SSL_set1_host`. The JS lane walks the chain
  itself, checks the **leaf's** validity window and matches anchors by
  subject + SPKI, so cross-signed chains end chains. Both lanes SNI the
  original host. The package has no custom-CA, client-cert or
  SNI-override API, only `*_insecure` (`verify=False`) for loopback.

## Publish

One command uploads `lib/package.bend` with everything it imports and
prints the import lines. No sign-up: proof of work takes its place. No
`TODO` or open law can land. `law fetch` is filled by `def fetch`. The
`@unsafe` defs are the HTTP echo and WS accept/event loops, and the byte
effects carry their `.c`/`.js` twins.

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
`~/.bend/lib` and checks it against its hash. Later runs read the cache
and never go online. Every fix is a new hash. A consumer upgrades when it
pastes the new line.

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
bend tests/io/tcp_bytes_loopback.bend # 11 (two lanes, one line each)
bend tests/io/dns_resolve.bend        # 11111111111111
bend tests/io/dns_addr_form.bend      # 11111111 (pure addr_form vectors, incl. beef1.cafe)
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
bend tests/io/wsm_got_contra.bend      # 25 (got contra-proof: one-walk peel vs take/drop)
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
bend tests/io/wsm_got_contra.bend           # 25 (got contra-proof: peel vs take/drop)
bend tests/io/httpx_miniunit.bend           # 1
bend tests/io/httpx_client.bend             # 1
bend tests/io/httpx_interop.bend            # 1
bend tests/io/httpx_client_once.bend        # 1
bend tests/io/httpx_client_keepalive.bend   # 3
bend tests/io/httpx_client_request.bend     # 7   (4 chained + reset + H1 reuse)
bend tests/io/httpx_client_concurrent.bend  # 4
bend tests/io/httpx_client_stream.bend      # 1
bend tests/io/httpx_server_stream.bend      # 2
bend tests/io/httpx_stream_concurrent.bend  # 4 (cancel resets one stream, siblings continue)
bend tests/io/httpx_client_stream_concurrent.bend  # 3 (client slots: cancel one, siblings finish)
bend tests/io/httpx_client_stream_concurrent_skip.bend  # 1 (frames in flight of a dropped stream)
bend tests/io/httpx_client_stream_concurrent_plain.bend  # 5 (N clear H1 connections at once, alias server)
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
bend tests/io/httpx_got_contra.bend         # 52 (got contra-proof: split arms, projections, taken)
bend tests/io/httpx_h1_chunk.bend           # 35 (pure chunked decoder: vectors, step, reference equivalence)
bend tests/io/httpx_h1_fetch_chunk.bend     # 8 (chunked response end to end, truncated -> 400)
bend tests/io/httpx_h1_server_chunk.bend    # 6 (chunked request end to end: 200, 400, 413, keep-alive, upgrade lane)
bend tests/io/httpx_h1_upgrade.bend         # 7 (101 detaches the socket: server + client)
bend tests/io/httpx_h1_upgrade_client.bend  # 7 (renderer + raw peer + 200 -> 502)
bend tests/io/tcp_listen_backlog.bend       # 20 (20-client burst through the deep listener + fail-closed paths)
bend tests/io/tls_alpn_none.bend            # 1111 (no-ALPN client vs strict + dual servers)
bend tests/io/httpx_h2_goaway.bend          # 6 (typed stream verdicts: goaway/rst shapes)
bend tests/io/httpx_utf8_str.bend           # 31 (stack-safe text lanes: 64 KB ASCII, 20 K multi-byte)

bend tests/io/httpx_request.bend       # 2 (String + bytes bodies vs mini server)
bend tests/io/core_contract.bend          # 1 (core contract + header helpers + Fail codes)
bend tests/io/core_read_url.bend          # 1 (core URL vectors + valid_* gates)
```

Each file ends with a `#|` line that holds the expected output. That line
is the golden, but `bend` itself does not compare it: a test that prints
something else still exits 0. `./check.sh --tests` compares the golden, so a
changed answer fails there. A hand run of `bend <file>` prints the value
only, so capture stdout and diff it when you run one by hand. Do not trust
the exit status alone. A file with no
`main` (like `lib/package.bend`) instead prints `All terms check.` The
echo server's `@unsafe` annotation is expected.
JS and C lanes:

```sh
bend tests/io/httpx_h1_pure.bend -o /tmp/pure.js && bun /tmp/pure.js
bend tests/io/httpx_h1_pure.bend -o /tmp/purebin && /tmp/purebin
```

## Note on the byte effects and `lib/tcp.bend` / `lib/dns.bend`

`lib/wsm.bend` and `lib/ws.bend` import `./tcp.bend as TCPB` / `as TCP`
and call `TCP.send_bytes` / `TCP.recv_bytes` / `TCP.recv_frame`;
`lib/http.bend` imports `./dns.bend as DNS` and calls `DNS.resolve`. The
effects stay in the package (not in `Base`). That choice makes the bundle
self-contained. A hub consumer with a stock Base can
`import 0x<hash>/lib/wsm.bend as WSM` (or the superseded
`0x<hash>/lib/ws.bend as WS`) and compile.

The effect host symbols are the defs' local names:
`send_bytes_run`, `recv_bytes_run`, `recv_frame_run`, and the JS
functions `send_bytes`, `recv_bytes`, `recv_frame`. The `TCP` in a call
site comes from the import alias. The same holds for the resolver: the
effect def is `dns_lookup` (`dns_lookup_run` / `dns_lookup`,
`CID_DNS_LOOKUP`) and the public `resolve` is a pure wrapper in
`lib/dns.bend`. A def named `TCP.recv_frame` instead compiles to the host
`tcp_recv_frame`. That is the shape of the parallel `bend2/` Base patch,
so the two trees are not interchangeable.

`lib/tcp.bend` also carries the one listener the runtime cannot express:
`listen_backlog(port, backlog)` (`listen_backlog_run` / `listen_backlog`,
`CID_LISTEN_BACKLOG`). Backlog 0 fails with EINVAL and a busy port with
EADDRINUSE, both as the errno code plus its message. Four of the five TLS
effects share one more shape: their `.js` twins load
`lib/effs/tls_rt.js` (the portable TLS 1.2+1.3 runtime) by the
**cwd-absolute require**. That require is the only path that resolves in
every JS lane (interp, bun, node, emitted). The loaded module is cached
in the global slot `BEND_TLS_RT`, so the module body runs once per
process. The fifth, `tls_close.js`, needs no loader at all, because it
runs off the pump box the other four hand back. The `.c` twins keep
OpenSSL under `dlopen` for the binary lane. The cwd-absolute load finds
the runtime only when you run from the repo root. Every TLS socket the
package hands out, client or server, also turns Nagle off
(`TCP_NODELAY`). Without it the second of two small writes waits for the
peer's delayed ACK, which measured ~40ms per WSS connection (TASK-041).

### Picking a listener: `TCP.listen` vs `TCP.listen_backlog`

`TCP.listen` is Base's: one argument, and the runtime's own effect fixes
the accept queue at 16 (`listen(fd, 16)`, visible in the emitted C).
`TCP.listen_backlog` is the package's twin: the same listener
(SO_REUSEADDR, `0.0.0.0`, non-blocking, the errno as the fail code), with
the queue depth as an argument. Both names resolve under the same `TCP`
alias. The Base effect and the package's effects do not shadow each
other, so one import gives a file either or both:

```python
import Base
import ./tcp.bend as TCP      # from lib/; ../../lib/tcp.bend from examples/

# One peer at a time, or a test: the runtime's listener is enough.
def listen_once(port: U32) -> IO(Result<&1, &1, U32 & String, Listener>):
  TCP.listen(port)

# A server that can be dialed by more than one peer at once.
def listen_deep(port: U32) -> IO(Result<&1, &1, U32 & String, Listener>):
  TCP.listen_backlog(port, TCP.LISTEN_BACKLOG())
```

Why the depth is a choice and not a default (loopback, 8 cores,
TASK-041): the queue is a threshold, not a slope. The only thing that
changes across it is whether a dial loses its SYN and waits out the TCP
retry (~1s). Measured on one lane, each dial a new TLS connection:

| dials at once | `TCP.listen` (queue 16) | `TCP.listen_backlog(…, 128)` |
|---|---|---|
| 10 | 120-148ms | same — the queue is never full |
| 20 | ~1.08s | **~0.06s** (native), 234ms (interp) |

The accept path is what makes the queue fill at all: the server
handshakes TLS inline (~12ms per accept in the native runtime), so a
burst keeps arriving while the queue drains one connection at a time.
The rule:

- **one or a few peers, or a test** → `TCP.listen`;
- **a server whose peers can arrive together, or whose accept is slow per
  connection** → `TCP.listen_backlog(port, TCP.LISTEN_BACKLOG())`;
- **a load driver** → always the deep one; that is what
  `examples/wss/wsm_saturate.bend` does.

The server examples under `examples/` all listen deep now
(`httpx/httpx_echoserv`, `httpx/httpx_echo_server`,
`httpx/httpx_http1_server`, `httpx/httpx_server_stream`,
`httpx/httpx_site`, `wsm/server`, `wsm/server_on`,
`wss/wsm_frag_echo`, `wss/wsm_sub_echo`). The gate's `tests/io/*` keep
Base's `TCP.listen`: they dial one connection at a time, so the listener
choice does not move a number there. The one test that drives a burst
(`tests/io/tcp_listen_backlog.bend`) uses the deep one and fails if the
burst misses its budget. `examples/httpx/h2_big_loopback.bend` also keeps
Base's: it rides the superseded `lib/http2.bend` and opens exactly one
connection.

The C side targets the Bend 2.0.21 runtime: `io_wait_on(w, fd, evts,
time, more)` takes the deadline word (pass `0`), and `io_node` takes
four arguments.

## Roadmap

- HTTPS/WSS validation: interop WSS 4/4 + Bend→Node HTTPS PASS
  (Node→Bend FAIL documented: HPACK huffman), saturation 20/20 per lane
  (`examples/wss/wsm_saturate.bend`), bench 40 exchanges in ~15.2s interp
  / ~2.3s C (~2.6 vs ~17.8 ex/s).
- HPACK full: huffman decode + dynamic table + table-size updates;
  interop HTTPS bidirectional PASS; saturation 20/20 per lane (interp
  ~16.3s / C ~2.2s for 40 exchanges — see `tasks/task-023-perf.md`).
- HTTP/2 done (task-020, 2026-09-25): unbounded-slot interleaved mux,
  CONTINUATION, flow control with `WINDOW_UPDATE` (connection and
  stream), `MAX_FRAME_SIZE=65535`, `RST_STREAM`/`GOAWAY`/`PING` as
  protocol events, HPACK dynamic table on the client, ALPN HTTP/1.1
  fallback on the same port. Still out: h2c (cleartext), server push,
  HPACK Huffman *encode* (literal-only is valid), `PRIORITY`.
- TLS JS lane is portable: the five JS twins left `bun:ffi`/libssl for
  `lib/effs/tls_rt.js` (TLS 1.3 + 1.2 over the host's `crypto`), proven
  by the ~90-rung ladder (`tests/effs/tls-generic.sh`, green in node and
  bun, also against the installed files). Four install bugs (D44-D47)
  surfaced and were fixed with goldens. Dial-first contract on the same
  day (2026-10-13, task-047): the dial is `Base.TCP.connect`'s and the
  effect only handshakes, so `op.args[0]` is a real fd. The 20-client TLS
  burst measured ~29.0 s against ~35.3 s before.
- DNS resolver off libc (done 2026-10-12, commit `a01a6891`): the JS twin
  reads `/etc/resolv.conf` with the runtime's own `fs` instead of its own
  `dlopen`; the twin rules became `tests/effs/parity.sh` (26 passed, 0
  failed, 3 known).
- Stack-safe text lanes: `fetch` of a multi-MB body no longer overflows
  the interpreter stack; golden `tests/io/httpx_utf8_str.bend` (31).
- Open: the client HPACK dynamic table is per response, so a keep-alive
  connection does not reuse entries across responses; trailers and 1xx
  informational responses are not surfaced; no idle timeout exists on
  `keep-alive`.
- IPv6 (AAAA) resolution and connect: `dns.bend` answers A only.
- Cluster run of the suite (`--gate`) and a first hub `--publish`.
- Performance (task-023, DEFERRED): runs after the remaining tasks.
