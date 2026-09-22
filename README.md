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
lib/ws.bend               # WebSocket server + client (text/binary, control)
lib/wss.bend              # WebSocket Secure: WS over TLS (client + server)
lib/sha1.bend             # SHA-1 (FIPS 180-4), for the handshake accept
lib/b64.bend              # base64, for the handshake accept
lib/static.bend           # static-file handler on top of HTTP
lib/tcp.bend              # byte-level socket effects (C + JS twins)
lib/dns.bend              # DNS resolve: A lookup for name hosts (C + JS twins)
lib/tls.bend              # TLS client + server effects (C + JS twins, OpenSSL)
lib/http2.bend            # HTTP/2 codec + client/server over TLS (pure Bend)
lib/https.bend            # HTTPS facade: fetch/send_request + server_on over TLS+DNS+H2
lib/effs/tcp_send_bytes.* # send List<&2, U32> over a Socket
lib/effs/tcp_recv_bytes.* # receive bytes from a Socket
lib/effs/tcp_recv_frame.* # isolate exactly one WS frame, rest preserved
lib/effs/dns_resolve.*    # resolve a host to one IPv4 (getaddrinfo / UDP query)
lib/effs/tls_*.{c,js}     # TLS connect/accept/send/recv/close (dlopen libssl)
tests/io/http_lib_pure.bend   # pure layer: URL, headers, framing, chunked, UTF-8
tests/io/http_lib_fetch.bend  # IO: real loopback fetch + fail-closed paths
tests/io/http_lib_fetch_host.bend # IO: fetch by name over loopback, Host preserved
tests/io/http_lib_sec.bend    # security: CRLF/NUL injection, oversize, bad status
tests/io/tcp_bytes.bend       # IO: send_bytes/recv_bytes over loopback
tests/io/tls_connect_close.bend # IO: TLS loopback echo + fail paths (611/612)
tests/io/h2_loopback.bend       # IO: HTTP/2 echo over TLS (Bend↔Bend)
tests/io/https_*.bend         # HTTPS facade: fetch, streams, server_on, mux
tests/io/ws_*.bend            # WS crypto, handshake, frame, framing, message...
tests/io/wss_*.bend           # WSS loopback, server_on, client_on over TLS
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
`examples/https_real.bend` is a manual smoke against live hosts
(observed: `400`/`413` on example.com, cloudflare.com, info.cern.ch);
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
| `server_on(~H, l, cert, key, n)` | Generic keep-alive server (like `HTTP.server_on`): TLS accept loop with `IO.spawn` per connection, `n` extra streams per connection via `h2_serve_next`; `~H` is `H2Request -> IO(H2Response)` |
| `server_on_concurrent(~H, l, cert, key)` | Same accept loop; per connection a 2-slot interleaved mux (pipelined HEADERS/DATA of two open streams answered by sid; a third simultaneous stream fails the connection fail-closed) |
| `mux_start(~H, sock)` | One-shot concurrent serve on an established TLS socket (the test entry of the mux) |
| `echo.body` / `ok(body)` | Echo handler and `200` response helper |

Bodies are byte-faithful `List<&2, U32>` at the core (`encode_body` /
`decode_body` wrap `H2.str_bytes` / `H2.bytes_str`); headers are
`List<H2Hdr>` (`pairs_to_h2` / `h2_to_pairs` convert http-style pairs).
Fail codes surface unchanged: `400/413/502/503` (codec), `601-605`
(DNS), `611-616` (TLS).

**Scope:** the client speaks HTTP/2 over verified TLS (ALPN `h2`).
HPACK decode is full (see `## HTTP/2`): real-world `https://` hosts
fail closed only on CONTINUATION splits (`400`) or frames > 16384
(`413`); huffman/dynamic-table peers (node:http2, public sites)
decode fine. Loopback and Bend↔Bend remain the golden-tested path;
`examples/https_real.bend` documents the live smoke manually.

```sh
bend tests/io/https_fetch.bend        # 1
bend tests/io/https_streams.bend      # 1
bend tests/io/https_server_on.bend    # 1
bend tests/io/https_mux.bend          # 1
bend examples/https_real.bend         # manual; FAIL 400/413/502 (HPACK subset)
```

## WebSocket

`lib/ws.bend` (import as `WS`) is an RFC 6455 server and client:
handshake, frame codec, text/binary messages, ping/pong/close, masked
clients and unmasked server frames. The codec is pure; IO rides the
byte effects above. Fragmented frames (`FIN=false`) are refused with
`Fail 400`.

Handshake (pure):

| Function | Description |
|---|---|
| `accept_of` | `Sec-WebSocket-Accept` = base64(SHA1(key ++ GUID)) |
| `handshake` | Validate a raw request and build the `101` response, or `Fail 400` |
| `client_request` | Build the client upgrade request for host/path/key |

Frame codec (pure, bytes are `List<&2, U32>`):

| Function | Description |
|---|---|
| `read_frame` / `read_frame_unmasked` | Parse one frame into `fin & op & payload`, masked / unmasked |
| `show_frame` / `show_masked` | Render an unmasked frame / a client-masked frame |
| `frame_need` / `frame_split` | Length-prefix size, and incremental split into `FrameGot{frame, rest}` / `NeedMore{missing}` / `FrameBad` |
| `unmask` | XOR a payload with the four mask bytes |

Messages and events: `WSMessage` is `WSText{text}` or `WSBin{data}`;
`WSOut` is `OutMsg` / `OutOp` / `OutRaw`; `WSIn` is `InMsg` / `InOp`;
`WSEv` is the lifecycle event (`EvOpen`, `EvMsg`, `EvPing`, `EvPong`,
`EvClose`, `EvError`).

IO:

| Function | Description |
|---|---|
| `send_msg` / `send_op` / `send` | Send a message / an opcode+payload / a `WSOut` |
| `recv_msg` / `recv_op` / `recv` | Single-shot raw read (one `recv_bytes`); a read may split or glue frames |
| `recv_msg_framed` / `recv_op_framed` / `recv_in_framed` | One frame per call, the rest threaded back (`*_client_framed` for the client side) |
| `serve_once` | Server echo of one connection |
| `ws_serve` | Server accept loop (unsafe) |
| `server_on(~H, l)` | Event-driven server: `~H` maps `WSEv` to `IO(WSOut)`, one step per frame |
| `client_on(~H, host, port, path, key)` | Event-driven client, same `WSEv`/`WSOut` API, sends masked |
| `client_echo(host, port, path, key, msg)` | Connect, handshake, send, read the echo |

## WSS

`lib/wss.bend` (import as `WSS`) is WebSocket Secure: the same RFC 6455
API as `lib/ws.bend`, riding `lib/tls.bend`. Types (`WSEv`, `WSOut`,
`WSMessage`) come from `WS` — import both. The client dials with
`tls_connect_noalpn[_insecure]` (ALPN none: WSS is HTTP/1.1 Upgrade,
not h2); the server accepts with `tls_accept`. Every path closes via
`TLS.tls_close` (never `Socket.close`).

| Function | Description |
|---|---|
| `serve_once(sock)` | Single-shot server echo over one TLS socket |
| `server_on(~H, l, cert, key)` | Event-driven server: TLS accept loop, `IO.spawn` per connection, same `~H` as `WS.server_on` |
| `client_on(~H, host, port, path, key)` / `client_on_insecure` | Event-driven client over no-ALPN TLS, masked sends |
| `client_echo(...)` / `client_echo_insecure(...)` | Single-shot connect + handshake + one frame + echo |

Fail codes surface unchanged: WS `400`/`413`, DNS `601-605`, TLS
`611-616`.

```sh
bend tests/io/wss_loopback.bend    # 111
bend tests/io/wss_server_on.bend   # 1
bend tests/io/wss_client_on.bend   # 1111
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
`https_real.bend` is the HTTPS smoke (manual, may `Fail 400`/`413`/`502`
— HPACK subset / CONTINUATION); `server.bend` / `cliente.bend` are the
hand-driven WS session;
`server_on.bend` / `cliente_on.bend` are the same session over the
`server_on` / `client_on` event API; the `.js` files are `ws` npm peers
used for the interop matrix (WSS/HTTPS peers live alongside them).
`saturate_https_wss.bend` is the manual load driver (20 parallel
clients per lane over ephemeral ports; prints `SAT`/`BENCH` lines) —
never runs in the gate.

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

Interop matrix (loopback, test PEMs):

| Pair | Result |
|---|---|
| WSS node ↔ node / bun ↔ bun / node ↔ bun / bun → node | **4/4 PASS** |
| Bend `https_echo_client` → Node `https_server.js` | **PASS** (`DONE 3/3` / `DONE 1/1`) |
| Node `https_client.js` → Bend `https_echo_server.bend` | **PASS** (`DONE 4/4`; was `502 huffman refused` before HPACK-full) |
| Bend ↔ Bend HTTPS | **PASS** (golden `tests/io/https_*`, 4/4) |
| HPACK vectors (RFC C.4.1/C.6.1) + dynamic-table unit | **PASS** (`tests/io/hpack_huffman.bend` 11111111, `hpack_dyntab.bend` 11111111) |

## Security policy

- `show_*` rejects CRLF in every field with `Fail 400` (injection).
- `read_*` caps the head at 16 KB; oversize is `Fail 413`.
- Ports must be 1–65535; hosts reject whitespace, controls and NUL.
- `fetch` reads at most 8 × 8192 bytes (64 KB cap), then truncates.
- Name hosts resolve via `lib/dns.bend` (fail-closed, `Fail 601`–`605`);
  the resolved IP is transport-only — `Host` keeps the original name.

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
bend tests/io/http_lib_pure.bend      # 481441153
bend tests/io/http_lib_sec.bend       # 15
bend tests/io/http_lib_fetch.bend     # 111
bend tests/io/http_lib_fetch_cl.bend  # 111
bend tests/io/http_lib_fetch_post.bend  # 111
bend tests/io/http_lib_fetch_head.bend  # 11111
bend tests/io/http_lib_fetch_host.bend  # 111
bend tests/io/http_lib_server_on.bend   # 111
bend tests/io/tcp_bytes.bend          # 11
bend tests/io/tcp_bytes_loopback.bend # 1
bend tests/io/dns_resolve.bend        # 1111111111
bend tests/io/tls_connect_close.bend  # 111
bend tests/io/h2_loopback.bend        # 1
bend tests/io/https_fetch.bend        # 1
bend tests/io/https_streams.bend      # 1
bend tests/io/https_server_on.bend    # 1
bend tests/io/https_mux.bend          # 1
bend tests/io/ws_crypto.bend          # 8
bend tests/io/ws_handshake.bend       # 4
bend tests/io/ws_frame.bend           # 6
bend tests/io/ws_unmasked.bend        # 4
bend tests/io/ws_loopback.bend        # 111
bend tests/io/ws_msg.bend             # 1111
bend tests/io/ws_framing.bend         # 13
bend tests/io/ws_framed.bend          # 4
```

Each file ends with a `#|` line holding the expected output — that is the
PASS/FAIL gate. A file with no `main` (like `lib/package.bend`) instead prints
`All terms check.`; the echo server's `@unsafe` annotation is expected.
JS and C lanes:

```sh
bend tests/io/http_lib_pure.bend -o /tmp/pure.js && bun /tmp/pure.js
bend tests/io/http_lib_pure.bend -o /tmp/purebin && /tmp/purebin
```

## Note on the byte effects and `lib/tcp.bend` / `lib/dns.bend`

`lib/ws.bend` imports `./tcp.bend as TCP` and calls `TCP.send_bytes` /
`TCP.recv_bytes` / `TCP.recv_frame`; `lib/http.bend` imports
`./dns.bend as DNS` and calls `DNS.resolve`. Keeping the effects in the
package (rather than in `Base`) is what makes the bundle self-contained:
a hub consumer with a stock Base can `import 0x<hash>/lib/ws.bend as WS`
and compile.

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
  (`examples/saturate_https_wss.bend`), bench 40 exchanges in ~15.2s
  interp / ~2.3s C (~2.6 vs ~17.8 ex/s).
- HPACK full (done 2026-09-22, see `tasks/task-019-hpack-huffman-dyntab.md`):
  huffman decode + dynamic table + table-size updates; interop HTTPS
  bidirecional PASS; saturation 20/20 per lane (interp ~16.3s / C
  ~2.2s for 40 exchanges — see `tasks/task-020-perf.md`).
- HTTP/2 backlog: interleaved multiplexing (sequential + 2-slot mux
  today), CONTINUATION, h2c (cleartext). Live smoke already fails
  closed on CONTINUATION splits (`400 hpack eof*`) and frames
  > 16384 (`413`).
- IPv6 (AAAA) resolution and connect: `dns.bend` answers A only.
- Cluster run of the suite (`--gate`) and a first hub `--publish`.
