# bend-net

Pure HTTP networking for [Bend](https://bend-lang.com): an HTTP/1.1 client
and server written in user-land Bend on top of the existing `TCP.*` kit.
No TLS, no DNS, no foreign `.c`/`.js` files.

## Layout

```text
package.bend              # package entry (publish this file)
lib/http.bend             # the whole library (~1900 lines, imports Base only)
tests/io/http_lib_pure.bend   # pure layer: URL, headers, framing, chunked, UTF-8
tests/io/http_lib_fetch.bend  # IO: real loopback fetch + fail-closed paths
tests/io/http_lib_sec.bend    # security: CRLF/NUL injection, oversize, bad status
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
`@unsafe` is the echo accept loop).

```sh
bend package.bend --publish
# 0x<hash>
# import 0x<hash>/lib/http.bend as HTTP
```

The first run of an importer fetches the package from the hub into
`~/.bend/lib` and checks it against its hash; later runs read the cache
and never go online. Every fix is a new hash — consumers upgrade by
pasting the new line.

## Tests

```sh
bend tests/io/http_lib_pure.bend   # 441441153
bend tests/io/http_lib_sec.bend    # 15
bend tests/io/http_lib_fetch.bend  # 111
```

Each file ends with a `#|` line holding the expected output — that is the
PASS/FAIL gate. A file with no `main` (like `package.bend`) instead prints
`All terms check.`; the echo server's `@unsafe` annotation is expected.
JS and C lanes:

```sh
bend tests/io/http_lib_pure.bend -o /tmp/pure.js && bun /tmp/pure.js
bend tests/io/http_lib_pure.bend -o /tmp/purebin && /tmp/purebin
```

## Roadmap

- `lib/ws.bend`: WebSocket framing over this HTTP layer (shares the
  handshake: `read_head`/`show_request`), imported by the same
  `package.bend`, so one hash covers the unified `net`.
