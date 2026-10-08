# HTTPX: two delivery modes

`lib/httpx.bend` is one H2 codec with **two delivery disciplines**. Every
public entry belongs to exactly one of them; the handler signature tells
which. (Verified by grepping `~H:` — 102 hits, no third shape.)

## Mode 1 — whole response ("on/once")

The handler sees a **complete** request and answers a **complete**
response, with IO allowed (DB, upstream fetch, file reads):

- Server: `~H: Request -> IO(Response)`
- Client (concurrent scorer): `~H: Response -> U32` — same family, one
  score per complete response

| Entry | Loop (`lib/httpx.bend`) | Shape |
|---|---|---|
| `server.concurrent[_alpn]` | `httpx` (slots + interleaving) | N streams, any completion order |
| `server.on[_alpn]` / `server.on_h2` | `httpx_seq` | one stream at a time (ALPN split with one `~H` for both lanes) |
| `server.on_h1` / `server.once_h1` | `x_h1.srv.head` (phase 3 loops) | H1 keep-alive: answer, then read the next request on the same connection (`connection: close`, EOF, 413 and 502 close it) |
| `client.once[_insecure]` | `client_seq` (one request) or `x_h1.exch` on an H1 connection | 1 dial, stream 1, full `Response` |
| `client.connect[_insecure]` + `client.request`, `client.on` batch | `client_seq` on h2 / `client_seq.h1` on http/1.1 | 1 dial, answers in order: sids 1,3,5… and the HPACK table on h2; the one socket reused sequentially on H1 |
| `client.concurrent[_insecure]` | `client_conc.drain` (slots) | pipelined N, scored |
| `fetch[_bytes][_insecure]`, `request[_bytes][_insecure]` | `client.once` | URL / text conveniences |
| `h1_once[_insecure]` | `x_h1.exch` | H1 one-shot (TLS) |
| `fetch[_bytes]_insecure("http://…")` | `x_h1.exch` (TCP triple) | the same one-shot over plain TCP, no TLS |
| `server.on_h1_plain` / `server.echo_h1_plain` | `x_h1.srv.head` (TCP triple, phase 3 loops) | the same keep-alive H1 server over `TCP.accept`, no cert/key |

## Mode 2 — streaming (events)

The handler is a **pure classifier**: per event it decides `Continue`
(keep buffering) or `RespondEarly` / `Cancel`. No IO
inside — all IO (socket reads, `x_send_resp`, WU, RST, close) stays in
the loop. This buys O(1) per chunk and early answers without draining.

- Server: `~H: SrvEv -> SrvOut` (`SrvReqHead` / `SrvReqData` events, `Continue` / `RespondEarly` / `Cancel` answers)
- Client: `~H: StreamEv -> StreamOut` (`StreamHead` / `StreamData`; `StreamContinue` / `StreamCancel`)

| Entry | Loop | Shape |
|---|---|---|
| `server.stream[_alpn]` | `httpx_stream` (H2); `x_h1.stream.go` (H1) | upload events to a pure `~H`; `stream_alpn` dispatches H2/HTTP-1.1 by ALPN (`server.stream` stays H2-only behind `tls_accept`) |
| `server.stream_plain` | `x_h1.stream.go` (TCP triple) | plaintext H1 upload over `TCP.accept`, one request per connection, then close |
| `client.stream[_insecure]` | `client.on.sdrop` (H2); `x_h1.cli.stream.go` (H1) | download events to a pure `~H`; dispatches on `CliSt.is_h2` (`client_stream.dispatched`) |
| `client.stream_plain` | `x_h1.cli.stream.go` (TCP triple) | plaintext H1 download over `plain.dial`, then close |

## Shared substrate (no `~H`)

Both modes ride the same pieces: frame codec + HPACK, `x_read_frame`
(:861), flow pump `x_send_data_flow` (:2266), WU credit, CONTINUATION
(`client.on.cont_read`, :3167), preface/accept plumbing, slot ledgers
(`httpxn.*`, `httpxc.*`), the H1 lane (`x_h1.*`, both transports via the
`~recv`/`~send`/`~close` triple — see `docs/h1-transport.md`). Bodies
accumulate reversed (`x_rev_push`, un-reversed once with `x_cat`) so
multi-MB transfers never overflow the interpreter stack.

## Why streaming handlers must be pure

Two reasons, one load-bearing:

1. **Double-call determinism (H2 upload loop).** `httpx_stream` calls
   `H` **twice per event**: `httpxs.head_act_of` (which action code?)
   and `httpxs.head_resp_of` (which response?) — see phase 7. An IO (or
   otherwise non-deterministic) handler could answer differently each
   time and corrupt dispatch. Purity is what makes the two calls agree.
   The H1 lanes (`x_h1.stream.go`, `x_h1.cli.stream.go`) and the H2
   download lane (`client.on.sdrop`) instead call `H` **once** per event
   and decode the answer immediately (`head_act` / `data_act`) — same
   purity requirement, single call.
2. **Checker discipline (D9/D10).** IO in the handler would force
   `do`-blocks into phased dispatch plus mutual-recursion risk between
   loop and handler path; pure keeps every helper one-way.

Consequences (intentional, fail-closed): a streaming handler cannot
touch DB/upstream/files; `Continue` at `fin` is `Fail 500` (it must
answer early at fin). Symmetrically, the client never observes a
double `StreamHead` after CONTINUATION — the post-CONT decode rejoins
without re-delivering head.

## Rule of thumb

- Need IO while deciding (DB, upstream, files)? **on/once** (`server.concurrent`, `client.once`, …).
- Need incremental delivery (early response, O(1) chunks, no buffering)? **stream** (`server.stream[_alpn]` / `server.stream_plain`, `client.stream[_insecure]` / `client.stream_plain`), handler stays pure.

Live example of both disciplines, `examples/httpx/httpx_site.bend` (manual)
and `tests/io/httpx_site.bend` (gated): the site in `docs/site/` is served
by the whole-response handler, which reads each file per request with
`Static.read_bytes`. The streaming twin in the same test answers the same
routes from **literal** pages, and that is not a shortcut — a streaming
handler is pure, and `~H` is a *closed template* (`server.stream_plain(~mk(body), l)`
is rejected: "body is a variable here, not comptime"), so it can neither
read a file nor capture bytes read before the loop. See task-040 D1.

If a streaming handler ever needs IO, the redesign is single-call
(one `H` call returning an `(act, resp)` pair) plus `do`-blocks in the
phases — feasible, but checker-risky with no use case today.
