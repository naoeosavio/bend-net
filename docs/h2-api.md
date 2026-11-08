# HTTP/2 API contract

Version 1. Date 2026-11-07. Module `lib/http2.bend`, imported as `HTTP2`.
The test `tests/io/http2_api.bend` is the machine-checked copy of this
list: it has no `main`, and the typecheck fails when a promised name, a
parameter or a return type changes.

## The rule

- The promised surface is the set of entries below. A caller of the
  library uses these names.
- The `x_*` leaves are internal. A test may call one, and the module
  keeps them, but they are not a contract.
- Adding an entry keeps version 1. Removing an entry, renaming one,
  adding a required parameter or changing a return type raises the
  version.
- Every entry takes `+host`, `+port` and the typed `HTTP` records of
  `lib/http.bend`. The channel handlers are Bend functions: `~H` for a
  stream event, `~B` for a buffered request.

## Client entries

| Entry | Returns |
|---|---|
| `client.connect` | `Socket & HTTP.CliSt` (one connection) |
| `client.connect_insecure` | the same, without chain verification |
| `client.once` | one `HTTP.Response` |
| `client.once_insecure` | the same, no chain verification |
| `client.on` | a list of `HTTP.Response` |
| `client.on_insecure` | the same |
| `client.concurrent` | a `U32` score from `~H` |
| `client.concurrent_insecure` | the same |
| `client.request` | a `String` body |
| `request` | a `String` body from a path |
| `request_insecure` | the same |
| `request_bytes` | a byte body |
| `request_bytes_insecure` | the same |
| `fetch` | a `String` body from a URL |
| `fetch_insecure` | the same |
| `fetch_bytes` | a byte body from a URL |
| `fetch_bytes_insecure` | the same |
| `client.stream.once` | counts from the stream handler |
| `client.stream.once_insecure` | the same |
| `client.stream.on` | counts from the stream handler |
| `client.stream.on_insecure` | the same |
| `client.stream.concurrent` | counts from the concurrent handler |
| `client.stream.concurrent_insecure` | the same |
| `client.loop.on` | the socket and the stream counts, plus `HTTP.CliSt` |
| `client.loop.exch` | the same |

## Server entries

| Entry | Returns |
|---|---|
| `server.concurrent` | `IO(Unit)`, one buffered handler per request |
| `server.on` | the same, one request at a time per connection |
| `server.once` | one connection, then return |
| `server.stream.concurrent` | the stream handler form of `concurrent` |
| `server.stream.on` | the stream handler form of `on` |
| `server.stream.once` | one connection, stream form |

## What a caller must know

- The server announces `ENABLE_PUSH` 0, `MAX_CONCURRENT_STREAMS` 100,
  `INITIAL_WINDOW_SIZE` 65535 and `MAX_FRAME_SIZE` 65535. It enforces
  them: the 101st open stream answers `RST_STREAM` 7, a frame past
  65535 bytes answers `GOAWAY` 6, and a header block past 64 KiB answers
  `GOAWAY` 11.
- A fail is a number, never text: `400`/`413`/`431`/`502`/`503` from the
  HTTP lanes, `601-605` from DNS and `611-616` from TLS.
- `_insecure` means "no chain verify". The TLS handshake still runs.

## Not promised

`x_parse`, `x_frame_of`, `x_data_body`, `x_frame_write`, `x_send_frame`,
`x_send_goaway`, `x_send_rst`, `x_block`, `x_preface`,
`x_settings_initial_pay`, `x_req.decode`, `x_resp.decode`, `x_be32_rd`,
`x_tab.empty` and the other `x_*` leaves are internal helpers. The wire
tests name them. The library keeps them stable, and a change there
changes no version number.
