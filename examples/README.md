# examples

These interop programs are runnable, but they are **not published** with the
package and **not run** by the gate. `check.sh --checks` only typechecks
every `.bend` file here and runs `node --check` on every `.js` file. Run
these programs by hand. Almost always they need a second process (the peer
of the pair) or the public internet.

Run everything from the repository root. Then the relative imports and the
`tests/io/tls_test_*.pem` paths resolve:

```sh
bend examples/wsm/server.bend          # then, in another terminal:
bend examples/wsm/cliente.bend
```

## Families

The folders are the transport lanes. Each folder holds its **pairs** and its
**quadruples**. A pair is a server and the client that dials it. A quadruple
is the same session in Bend and in Node, hand-driven and event-driven. Any
server talks to any client of the same family unless noted.

### `wsm/` — `ws://`, plaintext WebSocket

The scripted session has 6 steps on `127.0.0.1:19880` (`/chat`):
`101 -> ping s1/pong -> ping c1/pong -> hello/echo -> ping s2/pong -> close`.
Each side prints one `OK` line per step. Each side also prints `DONE 6/6`.
A run passes when `DONE` is present and no `FAIL` is present.

| Server | Client | Shape |
|---|---|---|
| `server.bend` | `cliente.bend` | hand-driven socket loop, Bend ↔ Bend |
| `server_on.bend` | `cliente_on.bend` | `WSM.server.on` / `WSM.client.on` event API |
| `server.js` | `client.js` | npm `ws` peer |
| `server_on.js` | `client_on.js` | npm `ws`, event-driven (mirrors `*_on.bend`) |
| `server_native.js` | `client_native.js` | no dependencies (`node:net`), also runs under bun |

```sh
bend examples/wsm/server.bend
bend examples/wsm/cliente.bend
NODE_PATH=/tmp/wsport/node_modules node examples/wsm/server.js 19880
bun examples/wsm/server.js 19880          # builtin WebSocket, no NODE_PATH
node examples/wsm/server_native.js 19880  # no dependencies at all
```

### `wss/` — `wss://`, WebSocket over TLS

The test PEMs (`tests/io/tls_test_cert.pem` / `_key.pem`, CN `127.0.0.1`)
stand in for a CA. Each pair does one session. Then the pair closes.

| Server | Client | Port | What it proves |
|---|---|---|---|
| `wss_server.js` | `wss_client.js` | 19891 | the basic TLS echo handshake |
| `wss_hello_server.js` | `wsm_hello_client.bend` | 19892 | `101` + first frame coalesced in one segment |
| `wsm_frag_echo.bend` | *(any Node `ws` client, >16 KB)* | 19893 | real fragmentation on the wire |
| `wsm_sub_echo.bend` | `wss_sub_client.js` | 19894 | subprotocol negotiation (`["p1"]`) |
| `wsm_frag_client.bend` | *(Node `ws` echo, not in the tree)* | 19894 | 32000-byte binary message out and back |
| `wsm_saturate.bend` | — | ephemeral | load driver: 20 parallel clients on the HTTPS + WSS lanes, prints `SAT`/`BENCH` |
| `wsm_binance_bookticker.bend` | — | 443 | live public peer: `wss://stream.binance.com:9443/ws`, one `SUBSCRIBE`, prints `BOOK` lines until the 15 s sleep halts it |

```sh
NODE_PATH=/tmp/wsport/node_modules node examples/wss/wss_server.js 19891
NODE_PATH=/tmp/wsport/node_modules node examples/wss/wss_client.js 19891
bend examples/wss/wsm_saturate.bend            # manual bench, never in the gate
bend examples/wss/wsm_binance_bookticker.bend | head -20
```

The fragment pair needs a compiled binary. The interpreter faults past
~25 KB in a single transfer.

### `httpx/` — `lib/httpx.bend`: mini-H2, ALPN split and the H1 lanes

| Server | Client | Port | Lane |
|---|---|---|---|
| `httpx_echoserv.bend` | `mux_node_client.js` | ephemeral (prints `PORT`) | H2, `server.concurrent` |
| `mux_node_echoserv.js` | `httpx_client_once.bend`, `httpx_request.bend` | 19893 | H2-only echo, `client.once` / `request` |
| `https_server.js` | `httpx_echo_client.bend`, `httpx_big_client.bend` | 19892 | `node:http2` echo, 100 KB in `httpx_big_client` |
| `httpx_echo_server.bend` | `https_client.js` | 19893 | Bend H2 echo for a Node client (pass the port: `node https_client.js 19893`) |
| `httpx_http1_server.bend` | `https_http1_client.js` | 19895 | ALPN split: one handler, h2 **and** HTTP/1.1 |
| `httpx_server_stream.bend` | *(Node / raw client)* | 19895 | streaming upload, `server.stream` |
| `mux_node_bigserv.js` | *(streaming-download probe)* | 19894 | answers 100 KB, forces `WINDOW_UPDATE` credit |
| `h2_big_loopback.bend` | — | ephemeral | Bend ↔ Bend 100 KB on one stream |
| `h2_big_headers_client.js` | `httpx_echo_server.bend` | 19893 | ~25 KB header block: HEADERS + CONTINUATION |
| `httpx_site.bend` | *(a browser)* | 8080 + 8443 | this repo's own site (`docs/site/`) over plain H1 and TLS/ALPN |

```sh
NODE_PATH=/tmp/wsport/node_modules node examples/httpx/mux_node_echoserv.js 19893 1 &
bend examples/httpx/httpx_client_once.bend

# the site: http://127.0.0.1:8080/ and https://127.0.0.1:8443/
bend examples/httpx/httpx_site.bend
```

Big bodies need a compiled binary (`bend file.bend -o /tmp/bin && /tmp/bin`).
The interpreter faults past ~25 KB per transfer. The interpreter is far too
slow for the multi-MB bulk clients.

### `real/` — live public peers, by name

These programs are a manual smoke test against the internet. They need a
working resolver. They also need a peer that speaks the same subset
(HPACK/HTTP-2). The gate never runs them.

| Program | What it does |
|---|---|
| `httpx_real.bend` | `fetch`/`request` against `example.com`, `cloudflare.com`, `info.cern.ch` |
| `httpx_h1_real.bend` | the same idea on the plaintext H1 lane (`http://`) |
| `https_real.js` | the Node `node:http2` port of `httpx_real.bend`, same four targets |
| `httpx_client_once_bulk.bend` | `client.once` on Binance `exchangeInfo` (~5.8 MB) |
| `httpx_fetch_bulk.bend` | `fetch_bytes` on the same feed |

```sh
bend examples/real/httpx_real.bend
node examples/real/https_real.js
bend examples/real/httpx_fetch_bulk.bend -o /tmp/fetchbulk && /tmp/fetchbulk
```

## Listeners

Every server here listens with `TCP.listen_backlog(port,
TCP.LISTEN_BACKLOG())` from `lib/tcp.bend`. It does not listen with the
`TCP.listen` of Base. The reason is the accept queue. The listen call in the
runtime hardcodes 16. A peer burst larger than 16 makes the kernel drop the
excess SYNs. Each dropped dial then waits out the TCP retry (~1s).

The queue only shows up in bursts. 10 simultaneous dials take 120-148ms on
either listener. 20 simultaneous dials take ~1.08s on the 16-deep listener
and ~0.06s on the deep listener. A TLS accept is slow for each connection
(~12ms, the handshake runs inline). That delay keeps the queue full while it
drains. Another process dials these files, so the files take the depth:

```python
import Base
import ../../lib/tcp.bend as TCP
import ../../lib/httpx.bend as HTTPX

# The package's listener: same handle as TCP.listen, real queue depth.
def listen_deep(port: U32) -> IO(Result<&1, &1, U32 & String, Listener>):
  TCP.listen_backlog(port, TCP.LISTEN_BACKLOG())

def serve_listener(r: Result<&1, &1, U32 & String, Listener>) -> IO(Unit):
  match r:
    case Fail{e}:
      IO.die(Unit, 1, "listen failed")
    case Done{l}:
      serve(l)

def main() -> IO(Unit):
  do IO<Unit>:
    r : Result<&1, &1, U32 & String, Listener> <- listen_deep(19893)
    serve_listener(r)
```

Both names resolve under the same `TCP` alias. The `TCP.listen`,
`TCP.connect` and `TCP.accept` of Base do not shadow the
`TCP.listen_backlog` and `TCP.send_bytes` of the package. Thus a file that
needs the old listener — a one-peer test, or the superseded
`h2_big_loopback.bend` — does not have to import anything else. The rule and
the numbers are in the main `README.md` (`### Picking a listener`). The
gate's tests dial one connection at a time and keep `TCP.listen`. The
exception is `tests/io/tcp_listen_backlog.bend`, which drives the 20-client
burst.

## Ports

Fixed ports are per lane. Two families share a few numbers. Run one peer for
each port at a time:

| Port | Owner |
|---|---|
| 19880 | `wsm/` session |
| 19891–19894 | `wss/` peers |
| 19892–19895 | `httpx/` peers |
| 8080 / 8443 | `httpx/httpx_site.bend` (plain / TLS) |

## See also

- `README.md` — the library contracts and the golden tests.
- `docs/modes.md` — the two HTTPX delivery modes (`on`/`once` compared with
  `stream`).
- `docs/h1-transport.md` — the H1 lane over the `~recv`/`~send`/`~close`
  triple (TLS and plain TCP).
- `tasks/` — the engineering log: what each interop matrix measured and when.
