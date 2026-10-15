# HTTPX: two delivery modes

`lib/httpx.bend` holds one H2 codec and **two delivery disciplines**. Every
public entry belongs to exactly one discipline; the handler signature shows
which one. (A grep for `~H:` gives 102 hits and no third shape.)

## Mode 1 — whole response ("on/once")

The handler sees a **complete** request and answers a **complete**
response. The handler can do IO (DB, upstream fetch, file reads):

- Server: `~H: Request -> IO(Response)`
- Client (concurrent scorer): `~H: Response -> U32` — same family, one
  score per complete response

| Entry | Loop (`lib/httpx.bend`) | Shape |
|---|---|---|
| `server.concurrent[_alpn]` | `httpx` (slots + interleave) | N streams, any completion order |
| `server.on[_alpn]` / `server.on_h2` | `httpx_seq` | one stream at a time (ALPN split with one `~H` for both lanes) |
| `server.on_h1` / `server.once_h1` | `x_h1.srv.head` (phase 3 loops) | H1 keep-alive: answer, then read the next request on the same connection (`connection: close`, EOF, 413 and 502 close it) |
| `client.once[_insecure]` | `client_seq` (one request) or `x_h1.exch` on an H1 connection | 1 dial, stream 1, full `Response` |
| `client.connect[_insecure]` + `client.request`, `client.on` batch | `client_seq` on h2 / `client_seq.h1` on http/1.1 | 1 dial, answers in order: sids 1,3,5… and the HPACK table on h2; the one socket reused sequentially on H1 |
| `client.concurrent[_insecure]` | `client_conc.drain` (slots) | pipelined N, scored |
| `fetch[_bytes][_insecure]`, `request[_bytes][_insecure]` | `client.once` | URL / text conveniences |
| `h1_once[_insecure]` | `x_h1.exch` | H1 one-shot (TLS) |
| `fetch[_bytes]_insecure("http://…")` | `x_h1.exch` (TCP triple) | the same one-shot over plain TCP, no TLS |
| `server.on_h1_plain` / `server.echo_h1_plain` | `x_h1.srv.head` (TCP triple, phase 3 loops) | the same keep-alive H1 server over `TCP.accept`, no cert/key |

## Mode 2 — stream (events)

The handler is a **pure classifier**. For each event, the handler decides
`Continue` (keep the buffer) or `RespondEarly` / `Cancel`. The handler does
no IO; all IO (socket reads, `x_send_resp`, WU, RST, close) stays in the
loop. This design gives O(1) for each chunk and an early answer with no
drain.

- Server: `~H: SrvEv -> SrvOut` (`SrvReqHead` / `SrvReqData` events,
  `Continue` / `RespondEarly` / `Cancel` answers)
- Client: `~H: StreamEv -> StreamOut` (`StreamHead` / `StreamData`;
  `StreamContinue` / `StreamCancel`)

| Entry | Loop | Shape |
|---|---|---|
| `server.stream[_alpn]` | `httpx_stream` (H2); `x_h1.stream.go` (H1) | upload events to a pure `~H`; `stream_alpn` dispatches H2/HTTP-1.1 by ALPN (`server.stream` stays H2-only behind `tls_accept`) |
| `server.stream_concurrent[_alpn]` | `httpx_stream` (H2); `x_h1.stream.go` (H1) | the same contract with the H2 interleave loop: several uploads stay open on one connection, and each event carries its slot (task-053). A `Cancel` resets one stream (`RST_STREAM` 8) and the siblings continue. H1 stays one request for each connection |
| `server.stream_plain` | `x_h1.stream.go` (TCP triple) | plaintext H1 upload over `TCP.accept`, one request per connection, then close |
| `client.stream[_insecure]` | `client.on.sdrop` (H2); `x_h1.cli.stream.go` (H1) | download events to a pure `~H`; dispatches on `CliSt.is_h2` (`client_stream.dispatched`) |
| `client.stream_plain` | `x_h1.cli.stream.go` (TCP triple) | plaintext H1 download over `plain.dial`, then close |

## Shared substrate (no `~H`)

Both modes use the same pieces: the frame codec + HPACK, `x_read_frame`
(:861), and the flow pump `x_send_data_flow` (:2266). The other pieces are
WU credit, CONTINUATION (`client.on.cont_read`, :3167), the preface/accept
code, and the slot ledgers (`httpxn.*`, `httpxc.*`). The H1 lane is
`x_h1.*`; both transports use the `~recv`/`~send`/`~close` triple — see
`docs/h1-transport.md`. A body accumulates in reverse (`x_rev_push`) and
one `x_cat` un-reverses it, so a multi-MB transfer never overflows the
interpreter stack.

## Why a stream handler must be pure

Two reasons cause this rule; one reason is critical:

1. **Double-call determinism (H2 upload loop).** `httpx_stream` calls `H`
   **twice per event**: `httpxs.head_act_of` (which action code?) and
   `httpxs.head_resp_of` (which response?) — see phase 7. An IO handler,
   or any non-deterministic handler, can answer differently each time and
   can corrupt dispatch. Purity makes the two calls agree. The H1 lanes
   (`x_h1.stream.go`, `x_h1.cli.stream.go`) and the H2 download lane
   (`client.on.sdrop`) call `H` **once** per event and decode the answer at
   once (`head_act` / `data_act`). These lanes have the same purity
   requirement with a single call.
2. **Checker discipline (D9/D10).** IO in the handler can force
   `do`-blocks into phased dispatch and can add mutual-recursion risk
   between the loop and the handler path. A pure handler keeps every
   helper one-way.

The consequences are intentional and fail closed. A stream handler cannot
touch DB, upstream or files. `Continue` at `fin` is `Fail 500`, because the
handler must answer early at fin. In the same way, the client never sees a
double `StreamHead` after CONTINUATION; the post-CONT decode rejoins with
no second head delivery.

## Rule of thumb

- Use **on/once** (`server.concurrent`, `client.once`, …) if the handler
  needs IO to decide (DB, upstream, files).
- Use **stream** (`server.stream[_alpn]` / `server.stream_plain`,
  `client.stream[_insecure]` / `client.stream_plain`) for incremental
  delivery: an early response, O(1) chunks, no body buffer. The handler
  stays pure.

Two files show both disciplines: `examples/httpx/httpx_site.bend` (manual)
and `tests/io/httpx_site.bend` (gated). The site in `docs/site/` is served
by the whole-response handler, which reads each file per request with
`Static.read_bytes`. The stream twin in the same test answers the same
routes from **literal** pages, and that is not a shortcut. A stream handler
is pure, and `~H` is a *closed template*. The call
`server.stream_plain(~mk(body), l)` is rejected: "body is a variable here,
not comptime". So the handler can read no file and can capture no bytes
read before the loop — see task-040 D1.

If a stream handler ever needs IO, the redesign uses a single call: one `H`
call gives back an `(act, resp)` pair. The phases then need `do`-blocks.
That redesign is feasible, but it is risky for the checker, and no use case
exists today.
