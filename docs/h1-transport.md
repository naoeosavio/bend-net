# H1 transport templates (`~recv` / `~send` / `~close`)

`lib/httpx.bend` speaks HTTP/1.1 over **two transports** — TLS sockets
(`wss://`, `https://`) and plain TCP (`ws://`, `http://`) — with **one
grammar**. The grammar lives in `x_h1.*`; the transport arrives as three
template parameters threaded through every def that touches the wire:

| Template | Type | TLS instance | TCP instance |
|---|---|---|---|
| `~recv` | `Socket -> U32 -> IO(Socket & Result<&1,&1,U32 & String, List<&2,U32>>)` | `TLS.tls_recv_bytes` | `TCPB.recv_bytes` |
| `~send` | `Socket -> List<&2,U32> -> IO(Socket & Result<&1,&1,U32 & String, Unit>)` | `TLS.tls_send_bytes` | `TCPB.send_bytes` |
| `~close` | `Socket -> IO(Unit)` | `TLS.tls_close` | `Socket.close` |

Callers instantiate once, at the edge; everything below just forwards:

| Edge | Triple |
|---|---|
| `h1_once.conn` (TLS one-shot), `client.once.h1`, `client.on.h1_keep`, `client_seq.h1` | TLS |
| `h1_once.conn` (via `fetch.plain` / `fetch_bytes.plain`, after `TCP.connect`) | TCP |
| `h1_conn` (via `server.on_h1` / `server.once_h1`, via `httpxa_alpn_go`) | TLS |
| `h1_conn` (via `server.on_h1_plain`, after `TCP.accept`) | TCP |

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
  `x_h1.tcp_one` was added.

See `tasks/task-028-httpx-h1-upgrade-wsm.md` (Phase 1) for the migration
record: what was deleted, what was threaded, and the golden gate
(`.p28/suite.base.txt` vs `.p28/suite.p1.txt`, identical).
