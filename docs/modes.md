# HTTPX: two delivery modes

`lib/httpx.bend` is one H2 codec with **two delivery disciplines**. Every
public entry belongs to exactly one of them; the handler signature tells
which. (Verified by grepping `~H:` — 64 hits, no third shape.)

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
| `server.on_h1` | `x_h1.srv.head/bd` | H1 one-shot |
| `client.once[_insecure]` | `client_seq` (one request) or `x_h1.exch` on an H1 connection | 1 dial, stream 1, full `Response` |
| `client.connect[_insecure]` + `client.request`, `client.on` batch | `client_seq` | 1 dial, sids 1,3,5… (batch is H2-only; H1 gets 615) |
| `client.concurrent[_insecure]` | `client_conc.drain` (slots) | pipelined N, scored |
| `fetch[_bytes][_insecure]`, `request[_bytes][_insecure]` | `client.once` | URL / text conveniences |
| `h1_once[_insecure]` | `x_h1.exch` | H1 one-shot (TLS) |
| `fetch[_bytes]_insecure("http://…")` | `x_h1p.exch` | the same one-shot over plain TCP, no TLS |
| `server.on_h1_plain` / `server.echo_h1_plain` | `x_h1p.srv.head/bd` | the same H1 server over `TCP.accept`, no cert/key |

## Mode 2 — streaming (events)

The handler is a **pure classifier**: per event it decides `Continue`
(keep buffering) or `RespondEarly` / `Cancel`. No IO
inside — all IO (socket reads, `x_send_resp`, WU, RST, close) stays in
the loop. This buys O(1) per chunk and early answers without draining.

- Server: `~H: SrvEv -> SrvOut` (`SrvReqHead` / `SrvReqData` events, `Continue` / `RespondEarly` answers)
- Client: `~H: StreamEv -> StreamOut` (`StreamHead` / `StreamData`; `StreamContinue` / `StreamCancel`)

| Entry | Loop | Shape |
|---|---|---|
| `server.stream[_alpn]` | `httpx_stream` | upload events to a pure `~H` |
| `client.stream[_insecure]` | `client.on.sdrop` | download events to a pure `~H` |

## Shared substrate (no `~H`)

Both modes ride the same pieces: frame codec + HPACK, `x_read_frame`
(:525), flow pump `x_send_data_flow` (:1928), WU credit, CONTINUATION
(`cont_read`, :2829), preface/accept plumbing, slot ledgers
(`httpxn.*`, `httpxc.*`), the H1 lane. Bodies accumulate reversed
(`x_rev_push`, un-reversed once with `x_cat`) so multi-MB transfers
never overflow the interpreter stack.

## Why streaming handlers must be pure

Two reasons, one load-bearing:

1. **Double-call determinism.** The loop calls `H` **twice per event**:
   `httpxs.head_act_of` (which action code?) and `httpxs.head_resp_of`
   (which response?) — see `httpx_stream` phase 7. An IO (or otherwise
   non-deterministic) handler could answer differently each time and
   corrupt dispatch. Purity is what makes the two calls agree.
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
- Need incremental delivery (early response, O(1) chunks, no buffering)? **stream** (`server.stream`, `client.stream`), handler stays pure.

If a streaming handler ever needs IO, the redesign is single-call
(one `H` call returning an `(act, resp)` pair) plus `do`-blocks in the
phases — feasible, but checker-risky with no use case today.
