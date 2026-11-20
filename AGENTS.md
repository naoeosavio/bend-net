# AGENTS.md

bend-net: user-land HTTP/WS for Bend on top of the `Base.TCP.*` kit.
Published bundle is `lib/package.bend` (http + http1 + http2 + httpx + wsm
+ tcp + dns + tls + sha1 + b64).

## Use this, not that

- New code: `lib/httpx.bend` as `HTTPX` (the facade: H1 + H2 + HTTPS,
  client + server, plain + TLS, ALPN split, streaming, H1 `101` upgrade
  lane) and `lib/wsm.bend` as `WSM` (RFC 6455 `ws://` + `wss://` over the
  httpx upgrade lane).
- The H2 wire is `lib/http2.bend` as `HTTP2`: the frames, the HPACK codec,
  the flow pump and the H2 lanes. It does not dial or accept; the facade
  calls it. A caller that names an H2 leaf imports this file too.
- The H1 wire is `lib/http1.bend` as `HTTP1`: the request render, the head
  and body parsers, the reason table, the chunked codec, the keep-alive
  machine, the H1 stream lanes, the `101` upgrade machine and the
  per-connection runners. Its named entries own their transports
  (TASK-081 Phase 3): the client dials (`client.connect` TCP,
  `client.connect[_in]secure` TLS) and the server accepts
  (`server.accept` TCP, `server.accept_secure` TLS); the `.conn` arms keep
  `~recv`/`~send`/`~close` for a caller that owns its transport. A caller
  that names an H1 leaf imports this file too.
- The core is `lib/http.bend` as `HTTP`: the 25 Data types, the byte and text
  leaves, the string checks and the request validation. A caller that names a
  type or a leaf imports this file too, because Bend does not reexport.
- Deleted, do not restore: `lib/https.bend`, `lib/https_http1.bend`,
  `lib/ws.bend`, `lib/wss.bend`. HTTPX, WSM and the core superseded them.
  The old `lib/http1.bend` and `lib/http2.bend` are gone; their names hold
  the split modules of task-057 (all phases done).
- Native code lives only in `lib/effs/` (C + JS twins; JS lane rides `tls_rt.js`).
  Everything else is pure Bend.

## Commands (always from repo root)

Relative imports (`../../lib/x.bend`) and the cwd-absolute `tls_rt.js`
require break from any other directory. Bend 2.0.21+.

- Single test: `bend tests/io/<name>.bend`, then compare the last numeric
  output line against the trailing `#|N` golden in the file
  (bend itself does not check goldens; `check.sh` does).
- Focused gate: `bash check.sh <pattern>` — default runs only files changed
  since HEAD plus their importers. `bash check.sh --all` is the full gate.
  `--checks` / `--tests` split typecheck vs run. `BEND_TIMEOUT=<secs>`
  overrides the 150 s per-file ceiling.
- Typecheck only: `bend <file> --check-only`.
- Twin lint + units: `bash tests/effs/parity.sh`, `bash tests/effs/eff-unit.sh`.
- H2 conformance: `bash tests/conformance/h2spec.sh` builds the stress
  server, runs h2spec 2.6.0 and compares the failed tests with
  `tests/conformance/h2spec.expected`. Exit 0 = no new failure. A known
  failure that passes prints a line and does not fail. `H2SPEC=<bin>` and
  `H2SPEC_PORT=<port>` override the tool and the port.
- Publish: `bend lib/package.bend --publish` (imports are not transitive;
  import each API from its own file).

## Layout

- `lib/http.bend` — the core: types, leaves, request validation.
  `lib/http1.bend` — the H1 wire. `lib/http2.bend` — the H2 wire.
  `lib/httpx.bend` — the HTTP library: dial, accept, ALPN and the entries.
  `lib/wsm.bend` — the WebSocket library.
  `lib/tls.bend` — TLS dial/accept with ALPN modes. `lib/dns.bend` — A-record
  resolve. `lib/tcp.bend` — byte send/recv/frame effects.
- `tests/io/` — goldens: pure codec vectors plus loopback IO (each asserts via `#|N`).
  `tests/io/http2_api.bend` is the API contract of `lib/http2.bend` (no
  `main`, typecheck only); `tests/io/http2_perf.bend` holds the 2x budget
  of `docs/perf.md`.
- `tests/fuzz/` — `frames.bend` mutates one byte of five seed frames and
  `run.sh <secs>` loops it with new seeds; `wire.bend` injects malformed
  frames over TLS and expects GOAWAY or the close.
- `tests/effs/` — effects lab: twin parity, TLS interop ladder, bridge probes.
  `BEND_EFFS_DIR=lib/effs` runs ladder rungs against installed files.
- `examples/` — runnable peers by lane (`wsm/`, `wss/`, `httpx/`, `real/`);
  gate only typechecks them. `real/` hits live hosts, never in the gate.
- `tasks/` — engineering log (decisions, why-lanes-exist). `docs/modes.md`,
  `docs/tls-dns.md` — architecture that README compresses.

## Gotchas

- `.gitignore` is a whitelist (`*` ignored by default). Tracked: `lib/`,
  `examples/`, `docs/`, `tests/`, `task*`, root `README`/`package`/`AGENTS`/`LICENSE`.
  `src/`, root `*.bend`, `.scratch/` are untracked scratch — do not put code there.
  Run `git check-ignore -v <path>` before adding a new path.
- `check.sh` default (`--changed`) exits 0 with `nothing changed since HEAD`
  when nothing is touched — that proves nothing; use `--all` or a pattern for a real gate.
  Files under `tests/` without `def main` are contracts: reported, never run, never fail.
- TLS handle is opaque (session/pump box, never a raw fd): close with
  `TLS.tls_close`, never `Socket.close`. The dial is `Base.TCP.connect`'s;
  the effect only handshakes the already-connected fd.
- Fail codes are stable numbers, never text: DNS `601-605`, TLS `611-616`,
  HTTP `400/413/431/502/503`. DNS failures surface before any socket exists.
  The dial connects by resolved IP but `Host`/SNI keep the ORIGINAL name.
- Naming: `_insecure` means "no chain verify" (loopback/self-signed), never
  "no TLS". `_plain` means cleartext (`ws://`, `http://`) and takes no cert.
  No `is_tls` flags anywhere.
- H2 conformance is measured, not assumed: `docs/h2spec.md` holds the
  `h2spec` 2.6.0 run and the accepted deviations, and
  `tests/conformance/h2spec.sh` repeats the run. The request head checks
  the field rules of RFC 9113 8.2/8.3; a trailer block that ends the
  request answers it, and the trailer fields are dropped.
- H2 limits are announced and enforced, not advisory. `lib/http2.bend`
  announces `ENABLE_PUSH` 0, `MAX_CONCURRENT_STREAMS` 128, the 65535
  window and the 16384 frame cap (`MAX_FRAME_SIZE`) in its initial
  SETTINGS; a header block past 64 KiB answers `GOAWAY 11` on the server
  and `431` on the client; the 129th open stream answers `RST_STREAM 7`
  (REFUSED_STREAM). The buffered
  server form reads one chunk, admits every frame of the chunk before
  it answers one, and keeps a stream open while its answer waits in the
  queue, so a batch of HEADERS meets the cap (task-072). The stream
  form answers each event at once and holds no queue. A header block
  travels in 16384-byte slices (HEADERS plus CONTINUATION). A request
  copy drops `connection`, `keep-alive`, `proxy-connection`,
  `transfer-encoding`, `upgrade` and `te` before it reaches the wire.
  A buffered server request body is capped at 16 MiB (`x_max_body()`).
  Past the cap the lane answers `RST_STREAM 8` (CANCEL) and the handler
  never runs. For a bigger body use the stream lanes, which hold one
  chunk. A concurrent batch reads the peer preface first: the peer
  `MAX_CONCURRENT_STREAMS` (id 3) and `INITIAL_WINDOW_SIZE` (id 4) set
  the cap of the batch and the window of its first stream. A batch past
  the cap answers `503` (`batch past the peer cap`) before any stream
  opens. The chunked send-and-drain is not written (task-069 phase 5).
- A request head needs `:method`, `:scheme` and `:path` (RFC 9113 8.3.1),
  and the field rules of 8.2 (lowercase names, no connection-specific
  field, `te` only `trailers`, one of each pseudo-header). A CONNECT
  block (no `:path`) answers `501` and keeps the connection. A second
  HEADERS block on an open stream is a trailer block: the lane decodes
  its HPACK and answers the request when it ends the stream; the trailer
  fields do not reach the handler. No lane serves tunnels.
- Fail-closed codes: malformed input answers `Fail` with the code above, never
  a partial body. H1 head budget: 16 KB per request on the server
  (`431` past it), 64 KB total and 16 KB per line on the client
  (`413` — the fuel floor's code — past either); H1 server refuses
  `Transfer-Encoding` + `Content-Length` pairs, non-`chunked` TE, double
  `Content-Length`, missing/duplicate `Host` with `400` before reading a body byte.
