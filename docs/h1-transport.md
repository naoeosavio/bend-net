# H1 transport templates (`~recv` / `~send` / `~close`)

`lib/httpx.bend` speaks HTTP/1.1 over **two transports** — TLS sockets
(`wss://`, `https://`) and plain TCP (`ws://`, `http://`) — with **one
grammar**. The grammar lives in `x_h1.*`; the transport arrives as three
template parameters threaded through every def that touches the wire:

| Template | Type | TLS instance | TCP instance |
|---|---|---|---|
| `~recv` | `Socket -> U32 -> IO(Socket & Result<&1,&1,U32 & String, List<&2,U32>>)` | `TLS.tls_recv_bytes` | `TCP.recv_bytes` |
| `~send` | `Socket -> List<&2,U32> -> IO(Socket & Result<&1,&1,U32 & String, Unit>)` | `TLS.tls_send_bytes` | `TCP.send_bytes` |
| `~close` | `Socket -> IO(Unit)` | `TLS.tls_close` | `Socket.close` |

Callers instantiate once, at the edge; everything below just forwards:

| Edge | Triple |
|---|---|
| `h1_once.conn`, `h1_open.conn` (TLS one-shot dials), `x_h1.cli.exch` (via `client.on.h1_keep`) | TLS |
| `x_h1.cli.stream.exch` (streaming download, via `client_stream.dispatched` on the ALPN H1 answer) | TLS |
| `x_h1.stream.spawn` (streaming upload, via the `httpxs_alpn_go` False arm) | TLS |
| `h1_conn` (via `server.on_h1` / `server.once_h1`, via `httpxa_alpn_go`) | TLS |
| `h1_once.conn` (via `fetch.plain` / `fetch_bytes.plain`, after `TCP.connect`) | TCP |
| `x_h1.cli.stream.exch` (via `client.stream_plain`, after `plain.dial`) | TCP |
| `h1_conn` (via `server.on_h1_plain`, after `TCP.accept`) | TCP |
| `x_h1.stream.conn` (via `server.stream_plain`, after `TCP.accept`) | TCP |

## Why not two copies (like `ws.bend` / `wss.bend`)?

`lib/ws.bend` and `lib/wss.bend` each hardcode their transport: the whole
loop, handshake and split exist twice, once over `TCP.*` and once over
`TLS.*`. That works, but every fix lands twice — and the WebSocket
unification (`lib/wsm.bend`, task-028 Phase 4) needs **one** handshake
lane for `ws://` and `wss://`, not two lanes to choose between.

The H1 lane had the same disease: `x_h1.*` (TLS) plus a 28-def mirror
`x_h1p.*` (plaintext). It died in task-028 Phase 1. Without the collapse,
the 101-upgrade chain (Phase 2: `hd2_open` … `head_open` + `exch.open`;
Phase 3: `answer_open` + `on_h1_open`) would have been written twice —
and the bug that motivates Phase 2 (the `nbody=True` arm of `x_h1.cli.hd2`
dropping `rest`) would have needed fixing twice.

## Rules

- The triple rides the **first three parameters**, in `~recv, ~send,
  ~close` order, then `~H`, then the rest. (All recursive defs taking it
  are already `@unsafe`, so parameter order is free; uniformity is for
  the reader, not the checker.)
- **Pure defs take no triple**: `needs_body`, `sock_of`, `read_next`,
  `stop` never touch the socket — one copy serves both lanes.
- A `Bool is_tls` flag was rejected: it would put a `match` at each of
  the ~10 `recv`/`send`/`close` sites instead of one instantiation per
  edge. The `~H` handler precedent shows the dialect prefers a template
  over a flag.
- `h1_once.conn` is the shared post-dial runner: the dial differs
  (`h1_once.dial` vs `TCP.connect`), the grammar after it is one — so no
  `x_h1.tcp_one` was added. `client.stream_plain` is the same split for
  streaming download: `plain.dial`, then `x_h1.cli.stream.exch`.

## The streaming lanes (task-036 phase 6)

Upload (`x_h1.stream.*`, `~H: SrvEv -> SrvOut`) and download
(`x_h1.cli.stream.*`, `~H: StreamEv -> StreamOut`) ride the same triple,
so the TLS and plaintext instantiations share one grammar each:

- Upload: `x_h1.stream.go` reads the head (16KB a turn, 64 turns, the
  blank-line cut), frames like the one-shot server (GET/HEAD carry no
  body), and delivers one `SrvReqData` per body piece through
  `x_h1.stream.next` — the chunked step or the length-delimited cut
  (`x_h1.stream.cl_next`), whichever the head declared. Slot is 1 (H1
  has no stream ids). One request per connection, then close: no
  keep-alive, no pipelining. `RespondEarly` renders and closes, `Cancel`
  closes without responding, a malformed chunked body is 400.
- Download: `x_h1.cli.stream.go` frames through `x_h1.frame_of` (read
  back via the `x_h1.stream.frame_*` projections — Bend has no field
  access) and counts `(total bytes, chunks)` without buffering.
  `StreamCancel` closes and reports `Fail (8, "cancelled")` — there is
  no RST_STREAM on this lane. A peer that closes mid-body is 400 `eof`,
  the code the one-shot lane already answers.
- Both lanes call `H` **once** per event (unlike the H2 upload loop,
  which calls twice — see `docs/modes.md`) and decode to an act code
  (`head_act` / `data_act`). The framing `out` pair is only read in
  phase 6, so the dead hops carry a dummy — tuples are not `+`-bindable.

## The upgrade lane (task-028 Phases 2–3)

The 101 handshake reuses the same triple, extended with two more
templates: `~H: Request -> IO(Response)` (answers the handshake) and
`~K: Socket -> List<&2,U32> -> IO(Unit)` (owns the socket after it).

- Client: `x_h1.cli.exch.open` renders with `upgrade=True` and stops at
  the head (`head_open` chain). Non-101 is `Fail 502`, fail-closed.
  `h1_open`/`h1_open_insecure` dial (TLS) and return
  `Socket & Response & rest` — or close and `Fail` (`h1_open.rewrap`
  closes on `Fail`, since a refused handshake hands no socket over).
- Server: `x_h1.srv.answer_open` sends the 101 (`show_resp_head`: no
  `Content-Length`, no body) and calls `K(sock, rest)` — the socket
  **leaves** the keep-alive machine and never comes back to phase 3
  (returning would double-close or steal the frame bytes). Anything else
  answers through the normal `respond` and **rejoins** the machine
  (`rejoin` = `head` phase 3 with the leftover seed). The keep-alive
  machine itself is untouched.
- Handler `~K` defs take **plain binders** (`sock`, `rest`, not `+rest`):
  the `~K:` annotation matches un-annotated shapes.

See `tasks/task-028-httpx-h1-upgrade-wsm.md` (Phase 1) for the migration
record: what was deleted, what was threaded, and the golden gate
(`.p28/suite.base.txt` vs `.p28/suite.p1.txt`, identical).

## Who consumes the upgrade lane

`lib/wsm.bend` (the one WebSocket implementation, `ws://` + `wss://`) is
the only caller of the upgrade lane: the client side goes through
`h1_open[_insecure]` (TLS) and `x_h1.cli.exch.open` + `TCP.connect`
(cleartext), the server side through `on_h1_open` / `on_h1_open_plain`,
whose `~K` runs the frame loop on the socket the lane handed over. The
WSM's own surface — the `_plain` / TLS name map, the compat instances and
the name/type contract with the new tree (`lib/websocket/main.bend`) — is
documented in `README.md` (`## WebSocket (WSM)`) and in the task file
(Phase 6).
