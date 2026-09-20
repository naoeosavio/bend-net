# bend-net

HTTP/1.1 and WebSocket (RFC 6455) for [Bend](https://bend-lang.com),
written in user-land Bend on top of the `TCP.*` kit. No TLS, no DNS. The
only native code is the byte-level socket effect pair in `lib/effs/`.

## Layout

```text
package.bend              # package entry (publish this file)
lib/http.bend             # HTTP/1.1 library (~1900 lines, imports Base only)
lib/ws.bend               # WebSocket server + client (text/binary, control)
lib/sha1.bend             # SHA-1 (FIPS 180-4), for the handshake accept
lib/b64.bend              # base64, for the handshake accept
lib/static.bend           # static-file handler on top of HTTP
lib/tcp.bend              # byte-level socket effects (C + JS twins)
lib/effs/tcp_send_bytes.* # send List<&2, U32> over a Socket
lib/effs/tcp_recv_bytes.* # receive bytes from a Socket
lib/effs/tcp_recv_frame.* # isolate exactly one WS frame, rest preserved
tests/io/http_lib_pure.bend   # pure layer: URL, headers, framing, chunked, UTF-8
tests/io/http_lib_fetch.bend  # IO: real loopback fetch + fail-closed paths
tests/io/http_lib_sec.bend    # security: CRLF/NUL injection, oversize, bad status
tests/io/tcp_bytes.bend       # IO: send_bytes/recv_bytes over loopback
tests/io/ws_*.bend            # WS crypto, handshake, frame, framing, message...
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
import 0x<hash>/lib/http.bend as HTTP
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

## Security policy

- `show_*` rejects CRLF in every field with `Fail 400` (injection).
- `read_*` caps the head at 16 KB; oversize is `Fail 413`.
- Ports must be 1–65535; hosts reject whitespace, controls and NUL.
- `fetch` reads at most 8 × 8192 bytes (64 KB cap), then truncates.
- The TCP kit has no DNS: use IPs or `localhost`.

## Publish

One command uploads `package.bend` with everything it imports and prints
the import line. No sign-up: proof of work takes its place. No `TODO` or
open law can land (`law fetch` is filled by `def fetch`; the single
`@unsafe` is the echo accept loop, and the byte effects carry their
`.c`/`.js` twins).

```sh
bend package.bend --publish
# 0x<hash>
# import 0x<hash>/lib/http.bend as HTTP
# import 0x<hash>/lib/ws.bend   as WS
# import 0x<hash>/lib/sha1.bend as SHA1
# import 0x<hash>/lib/b64.bend  as B64
# import 0x<hash>/lib/tcp.bend  as TCP
```

The first run of an importer fetches the package from the hub into
`~/.bend/lib` and checks it against its hash; later runs read the cache
and never go online. Every fix is a new hash — consumers upgrade by
pasting the new line.

## Tests

```sh
bend tests/io/http_lib_pure.bend      # 441441153
bend tests/io/http_lib_sec.bend       # 15
bend tests/io/http_lib_fetch.bend     # 111
bend tests/io/tcp_bytes.bend          # 11
bend tests/io/tcp_bytes_loopback.bend # 1
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
PASS/FAIL gate. A file with no `main` (like `package.bend`) instead prints
`All terms check.`; the echo server's `@unsafe` annotation is expected.
JS and C lanes:

```sh
bend tests/io/http_lib_pure.bend -o /tmp/pure.js && bun /tmp/pure.js
bend tests/io/http_lib_pure.bend -o /tmp/purebin && /tmp/purebin
```

## Note on the byte effects and `lib/tcp.bend`

`lib/ws.bend` imports `./tcp.bend as TCP` and calls `TCP.send_bytes` /
`TCP.recv_bytes` / `TCP.recv_frame`. Keeping the effects in the package
(rather than in `Base`) is what makes the bundle self-contained: a hub
consumer with a stock Base can `import 0x<hash>/lib/ws.bend as WS` and
compile.

The effect host symbols are the defs' local names — `send_bytes_run`,
`recv_bytes_run`, `recv_frame_run`, and the JS functions `send_bytes`,
`recv_bytes`, `recv_frame` — while the `TCP` in a call site comes from
the import alias. (A def named `TCP.recv_frame` would instead compile to
the host `tcp_recv_frame`; that is the shape of the parallel
`bend2/` Base patch, so the two trees are not interchangeable.)

The C side targets the Bend 2.0.21 runtime: `io_wait_on(w, fd, evts,
time, more)` takes the deadline word (pass `0`), and `io_node` takes
four arguments.

## Roadmap

- TLS (`https://`, `wss://`): `fetch` currently refuses `https://` with
  `Fail 501`.
- Cluster run of the suite (`--gate`) and a first hub `--publish`.
