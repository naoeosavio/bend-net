# H1 transport templates (`~recv` / `~send` / `~close`)

`lib/httpx.bend` speaks HTTP/1.1 over **two transports**: TLS sockets
(`wss://`, `https://`) and plain TCP (`ws://`, `http://`). One grammar
serves both transports. The grammar lives in `x_h1.*`. The transport
arrives as three template parameters. Every def that touches the wire
receives these parameters:

| Template | Type | TLS instance | TCP instance |
|---|---|---|---|
| `~recv` | `Socket -> U32 -> IO(Socket & Result<&1,&1,U32 & String, List<&2,U32>>)` | `TLS.tls_recv_bytes` | `TCP.recv_bytes` |
| `~send` | `Socket -> List<&2,U32> -> IO(Socket & Result<&1,&1,U32 & String, Unit>)` | `TLS.tls_send_bytes` | `TCP.send_bytes` |
| `~close` | `Socket -> IO(Unit)` | `TLS.tls_close` | `Socket.close` |

A caller instantiates the triple one time, at the edge. All defs below the
edge only forward the triple:

| Edge | Triple |
|---|---|
| `h1_once.conn`, `h1_open.conn` (TLS one-shot dials), `x_h1.cli.exch` (through `client.on.h1_keep`) | TLS |
| `x_h1.cli.stream.exch` (stream download, through `client_stream.dispatched` on the ALPN H1 answer) | TLS |
| `x_h1.stream.spawn` (stream upload, through the `httpxs_alpn_go` False arm) | TLS |
| `h1_conn` (through `server.on_h1` / `server.once_h1`, through `httpxa_alpn_go`) | TLS |
| `h1_once.conn` (through `fetch.plain` / `fetch_bytes.plain`, after `TCP.connect`) | TCP |
| `x_h1.cli.stream.exch` (through `client.stream_plain`, after `plain.dial`) | TCP |
| `h1_conn` (through `server.on_h1_plain`, after `TCP.accept`) | TCP |
| `x_h1.stream.conn` (through `server.stream_plain`, after `TCP.accept`) | TCP |

## Why not two copies (like `ws.bend` / `wss.bend`)?

`lib/ws.bend` and `lib/wss.bend` each hardcode the transport. The loop, the
handshake and the split exist two times, once over `TCP.*` and once over
`TLS.*`. That design works, but every fix lands two times. The WebSocket
unification (`lib/wsm.bend`, task-028 Phase 4) needs **one** handshake lane
for `ws://` and `wss://`, not two lanes to choose between.

The H1 lane had the same problem: `x_h1.*` (TLS) plus a 28-def mirror
`x_h1p.*` (plaintext). Task-028 Phase 1 removed the mirror. The collapse
prevents a second copy of the 101-upgrade chain (Phase 2: `hd2_open` …
`head_open` + `exch.open`; Phase 3: `answer_open` + `on_h1_open`). The
collapse also prevents a second fix of the bug that motivates Phase 2: the
`nbody=True` arm of `x_h1.cli.hd2` drops `rest`.

## Rules

- The triple occupies the **first three parameters**, in `~recv, ~send,
  ~close` order. `~H` comes next, then the rest. All recursive defs that
  take the triple are already `@unsafe`, so parameter order is free.
  Uniformity helps the reader, not the checker.
- **A pure def takes no triple**: `needs_body`, `sock_of`, `read_next` and
  `stop` never touch the socket. One copy serves both lanes.
- The design rejects a `Bool is_tls` flag. The flag puts a `match` at each
  of the ~10 `recv`/`send`/`close` sites, not one instantiation for each
  edge. The `~H` handler precedent shows that the dialect prefers a
  template over a flag.
- `h1_once.conn` is the shared post-dial runner. The dial differs
  (`h1_once.dial` or `TCP.connect`), but the grammar after the dial is the
  same, so the design adds no `x_h1.tcp_one`. `client.stream_plain` is the
  same split for stream download: `plain.dial`, then
  `x_h1.cli.stream.exch`.

## The stream lanes (task-036 phase 6)

Upload (`x_h1.stream.*`, `~H: SrvEv -> SrvOut`) and download
(`x_h1.cli.stream.*`, `~H: StreamEv -> StreamOut`) use the same triple. The
TLS instantiation and the plaintext instantiation therefore share one
grammar.

- Upload: `x_h1.stream.go` reads the head (16KB a turn, 64 turns, the
  blank-line cut), then frames like the one-shot server; GET/HEAD carry no
  body. It delivers one `SrvReqData` for each body piece through
  `x_h1.stream.next`: the chunked step or the length-delimited cut
  (`x_h1.stream.cl_next`), whichever the head declared. The slot is 1,
  because H1 has no stream ids. One request for each connection, then
  close: no keep-alive, no pipelined requests. `RespondEarly` renders and
  closes; `Cancel` closes with no response; a malformed chunked body is 400.
- Download: `x_h1.cli.stream.go` frames through `x_h1.frame_of` and reads
  the frame back through the `x_h1.stream.frame_*` projections, because
  Bend has no field access. It counts `(total bytes, chunks)` with no
  buffer. `StreamCancel` closes and reports `Fail (8, "cancelled")`; this
  lane has no RST_STREAM. A peer that closes mid-body is 400 `eof`, the
  code that the one-shot lane already answers.
- Both lanes call `H` **once** for each event, but the H2 upload loop calls
  `H` twice — see `docs/modes.md`. The lanes decode to an act code
  (`head_act` / `data_act`). Only phase 6 reads the `out` pair from the
  frame step, so the dead hops carry a dummy; tuples are not `+`-bindable.

## The upgrade lane (task-028 Phases 2–3)

The 101 handshake reuses the same triple, and adds two more templates.
`~H: Request -> IO(Response)` answers the handshake, and
`~K: Socket -> List<&2,U32> -> IO(Unit)` owns the socket after it.

- Client: `x_h1.cli.exch.open` renders with `upgrade=True` and stops at the
  head (`head_open` chain). A non-101 answer is `Fail 502`, fail closed.
  `h1_open`/`h1_open_insecure` dial (TLS) and return
  `Socket & Response & rest`, or close and `Fail`. `h1_open.rewrap` closes
  on `Fail`, because a refused handshake gives no socket.
- Server: `x_h1.srv.answer_open` sends the 101 (`show_resp_head`: no
  `Content-Length`, no body) and calls `K(sock, rest)`. The socket
  **leaves** the keep-alive machine and never comes back to phase 3; a
  return can double-close the socket or steal the frame bytes. Any other
  answer goes through the normal `respond` and **rejoins** the machine
  (`rejoin` = `head` phase 3 with the leftover seed). The keep-alive
  machine itself stays untouched.
- A handler `~K` def takes **plain binders** (`sock`, `rest`, not
  `+rest`): the `~K:` annotation matches un-annotated shapes.

The file `tasks/task-028-httpx-h1-upgrade-wsm.md` (Phase 1) holds the
migration record: what was deleted, what was threaded, and the golden gate
(`.p28/suite.base.txt` and `.p28/suite.p1.txt`, identical).

## Who consumes the upgrade lane

`lib/wsm.bend` (the one WebSocket implementation, `ws://` + `wss://`) is
the only caller of the upgrade lane. The client side goes through
`h1_open[_insecure]` (TLS) and `x_h1.cli.exch.open` + `TCP.connect`
(cleartext). The server side goes through `on_h1_open` /
`on_h1_open_plain`; their `~K` runs the frame loop on the socket that the
lane handed over. The documentation of the WSM surface is in `README.md`
(`## WebSocket (WSM)`) and in the task file (Phase 6). This surface holds
the `_plain` / TLS name map, the compat instances and the name/type
contract with the new tree (`lib/websocket/main.bend`).
