# DNS and TLS: how the package built its own lanes, and why

`bend-net` receives no name-checked transport. Base speaks TCP by IP, and
the Bend runtime carries no TLS and no resolver. Thus the package owns
everything to the left of the byte stream:

- `lib/dns.bend` changes names into IPv4 addresses.
- `lib/tls.bend` gives privacy and authentication over that stream.

Both are **byte effects with twins** under `lib/effs/`, in the same shape
as `lib/tcp.bend`. This document answers how the package built them and
why. The evidence trail keeps the answers honest: the lab under
`tests/effs/` (gates, probes and the staged copies) and the git history.

The short version: **compose in Bend what the host cannot do, use the
host for cryptography, and fail closed with stable numbers on anything
that is not proven.**

## Why the package owns DNS and TLS

- `fetch` and `client.*` take **name hosts** (`https://example.com`).
  A resolver is necessary, and Base has none.
- WSS and HTTPS are the lanes that real peers speak. A WebSocket or HTTP
  lane without TLS cannot talk to them. Base has no TLS.
- The bundle must stay **self-contained**: a hub consumer with a stock
  Base compiles it. Thus the effects carry their twins, and the package
  needs no Base patch. The HTTP byte effects use the same argument. See
  the README, "Note on the byte effects".

## DNS: one A record, package-local

`lib/dns.bend` exports one entry: `resolve(host) ->
IO(Result<&1, &1, U32 & String, String>)`. The shape is deliberate:

- **A pure shell answers everything it can before the effect runs.** A
  canonical dotted quad answers itself. A host that is an **address
  form** but not canonical (`256.1.1.1`, `01.2.3.4`, `127.1`, `0x7f.1`)
  fails `601` in this shell, before the effect, on both lanes. Reason:
  libc reads those strings as IPs (`01.2.3.4` as `1.2.3.4`, `127.1` as
  `127.0.0.1`). This guard keeps the lanes equal (task-051 A2), and the
  test pins the four cases. `localhost` answers `127.0.0.1`. A name that
  fails the host checks (printable ASCII, 253 bytes at most, dot-labels
  1-63) fails `601` before any syscall. The shell is total and fails
  closed.
- **The effect (`dns_lookup`) is a C/JS twin pair**, like the byte
  effects. The **C twin uses `getaddrinfo`** on the helper thread of
  `io_work`, so the interpreter loop stays free. The **JS twin writes
  one A query over UDP** to the first IPv4 nameserver in
  `/etc/resolv.conf`, through a guarded `require("fs")`. It skips IPv6
  entries, because the `io_addr` of the runtime parses dotted quads
  only. It falls back to `127.0.0.53` when the file names no usable
  server. It parks on the socket with a 3 s deadline (`io_park_on`),
  retries one time on silence, and answers the first A record. The
  answer buffer holds 512 bytes. The twin has no TCP fallback for a
  truncated reply, and it answers A records only. The README states the
  same limits as out of scope (`AAAA`/IPv6, `h2c`).
- **The fail codes are stable numbers, never resolver text**: `601` bad
  host, `602` not found, `603` try again, `604` no IPv4, `605` resolve
  error. The twins reach the codes in different ways. The C twin maps
  the EAI verdicts (`602` EAI_NONAME, `603` EAI_AGAIN, `604` no AF_INET
  answer, `605` default). It answers `601` only for a NUL byte, because
  the pure layer already gates the rest. The JS twin maps NXDOMAIN to
  `602`, SERVFAIL and the second timeout to `603`, an answer with no A
  record to `604`, and each socket or malformed-answer path to `605`.
  Evidence limit: `tests/io/dns_resolve.bend` (golden
  `11111111111111`) pins the fast paths and the `601` checks only. Each
  case in that file is hermetic. The effect codes `602`-`605` live in the
  tables of the twins, and the manual real-host example
  (`examples/real/httpx_h1_real.bend`) exercises them.
- **The resolved IP is for the transport only.** The caller connects by
  the address, but it sends the ORIGINAL host in `Host` and in SNI.
  Virtual hosting never changes. `lib/dns.bend` and `lib/tls.bend` state
  this invariant, and it keeps `fetch` by name honest.

### The change of 2026-10-12: `bun:ffi` leaves the resolver

The JS twin read `/etc/resolv.conf` through libc itself (`dlopen`, with
the `dns_file` and `dns_ip` helpers), because `bun:ffi` was already in
the tree for the TLS twins. Commit `a01a6891` ("replace bun:ffi with
runtime fs in DNS resolver") replaced that code with the file effects of
the runtime: a bare `require("fs")`, the same way the runtime reads a
file. **Why:** `fs` is the one socket-adjacent builtin that resolves in
every JS lane (bare specifier, no host prefix). A second `dlopen` made
the resolver the only effect with its own libc binding. The same commit
made the twin rule formal. See the next section.
`lib/effs/dns_resolve.js` now holds no helper beyond what the query
needs.

## The twin rule, checked by a lint (`tests/effs/parity.sh`)

The compiler wraps each JS twin in **one closure for each file**, and
loads it through `io_sys()`. Thus the shape is not taste; it is what
compiles. `tests/effs/parity.sh` (26 passed, 0 failed, 3 known) lints
every twin against the rules that the effs of the runtime obey. The
rules come from `~/.bend/bend2/effs/*.js`, read on 2026-10-12. The lint
never opens that directory; it only encodes what it saw there.

- **Generic or nothing.** Each `require()` specifier is a bare name
  (`fs`, `crypto`, `tls`). The `node:*` and `bun:*` spellings belong to
  one host, so they are wrong. A relative path resolves in no lane. A
  guard (`try {` before a require) stops a missing module from aborting
  the page bundle.
- **No file or directory named after a host.** The `.c`/`.js` choice
  happens at compile time, so a per-host branch would have to live
  inside one file.
- **One helper lives in one twin.** Each twin is its own closure in the
  emitted bundle, so a repeated definition is duplication, not reuse.
  `tests/effs/twin_shared.bend` proves the other side: one file that
  serves two defs holds module state one time (golden 26, 2+20+4 and not
  14).
- **Syntax**: `node --check` on every twin. This check is the only
  syntax gate of the JS lane.

One accepted require is not a specifier: it is **cwd-absolute**. Four of
the five TLS effects load the shared runtime with
`require(process.cwd() + "/lib/effs/tls_rt.js")`. Measurement shows that
this path is the only one that resolves in interp, bun and node alike.
Thus one runtime file serves the four twins that handshake, and the lint
still passes. The orphan check of the lint knows both kinds of user. The
fifth twin, `tls_close.js`, loads nothing: it uses the pump box that the
other twins hand back. Thus the `reuse` check of the lint sees the
loader in four files, not in five.

## TLS: one contract, two wire implementations

`lib/tls.bend` (import as `TLS`) keeps a **public contract** that no
rewrite has moved: five raw defs (`tls_connect_raw`, `tls_accept_raw`,
`tls_send_bytes`, `tls_recv_bytes`, `tls_close`), the composed entries
that they drive, the fail-code family, and the routing below in Bend.

```bend
# One dial, composed in Bend (lib/tls.bend):
DNS.resolve(host)   # -> the IPv4 the connect rides (601-605 surface here)
TCP.connect(ip, port)  # -> the fd and its non-blocking mode (Base owns it)
tls_connect_raw(sock, host, verify, alpn)  # -> handshake only
```

| Piece | C lane (OpenSSL, dlopen) | JS lane (`lib/effs/tls_rt.js`) |
|---|---|---|
| Handle | SSL session box `{ssl, ctx, fd}` | pump box `{$: "TlsConn", pump, fd}`: never a raw fd, no SSL* |
| Handshake | `SSL_connect` on a **blocking** fd; the helper thread may block; `O_NONBLOCK` comes back on the success path, and each failure path closes the fd | portable pump, which parks on `WANT_READ`/`WANT_WRITE` of a non-blocking fd |
| Versions | the versions of OpenSSL | TLS 1.3 and 1.2, both in one ClientHello; the ServerHello of the peer picks; the effect never learns which |
| Crypto | libcrypto | the `crypto` builtin of the host: AEAD aes-128/256-gcm and chacha20-poly1305, probed by capability; ECDHE over the four groups in OFFERED_GROUPS; one x25519 share for each hello, the rest through an HRR re-share; PRF per RFC 5246; CBC-SHA256 for old peers |
| Modules | dlopen libssl, no link flags | bare `crypto`/`tls`/`fs` only: no `bun:ffi`, no libssl, no JSCallback; four of the five twins load it, and `tls_close` uses the handle |
| Verify | chain and hostname (`SSL_set1_host`) | chain, the validity window of **every** certificate, and the hostname, against the store of the host (as OpenSSL's `X509_verify_cert` does); **trust anchors match by subject and SPKI**, so a cross-signed chain ends a chain (cloudflare.com measured); the hermetic `expired-chain` rung pins the intermediate case |
| Nagle | TCP_NODELAY on every fresh fd (measured ~40 ms for each connection without it) | the same, best-effort |

**Why two lanes:** the C lane is what the native binary target
(`bend -o bin`) compiles, and it stays because measurement shows the
fastest exchange. The JS lane is what interp, node and bun run today. It
must work where no libssl can load: the emitted page/JSS bundle lives in
a browser, and no libssl exists there. Thus its require set is bare and
guarded.

**Why the JS lane is a pure-JS runtime and not `require("tls")`:**
measurement, not taste.

1. The effect dispatch of the runtime is **synchronous and never rotates
   the event loop of the host**. A `tls.connect` or `TLSSocket` call
   from an effect never progresses. A Promise-returning twin (the
   `tls-effects` lane, `tests/effs/tls-effects/`) needs a runtime patch
   (`io_run` async) and fd semantics that Bun refuses ("Bun does not
   adopt fds"; the server legs of the lane are a versioned `SKIP` on
   1.2.15).
2. A Node/Bun **worker** bridge works for the client. For the server it
   makes an ownership problem: the listener fd does not cross threads in
   Bun. `Atomics.wait` on it deadlocks a server in the same process. A
   deadline park costs ~0 ms and is what the pump needs in any case,
   plus everything above it. The 233 ms stall of that measurement lives
   in the Fase 0 log (`tasks/task-043-js-lane-tls-pure.md`, D12), not in
   the lab gate. The gate keeps only the 40 ms ceiling and the mode-1
   hang.
3. The portable pump pays for itself: one code path in every JS host,
   verification that fails closed through our own chain walk, and the
   ladder in `tests/effs/tls-generic.sh` that proves the wire bytes
   against the system OpenSSL in TLS 1.3 **and** 1.2. Out of scope, with
   fail code `613` (see the header of `tls_rt.js`): TLS 1.0/1.1, static
   RSA and DHE, SHA1-MAC suites, renegotiation, client certificates,
   x448 (the crypto of bun cannot compute it) and SHA-384 ECDSA
   certificates. Session resumption is absent, not refused: the runtime
   ignores a `NewSessionTicket`, stores and offers no session, and every
   handshake is full. Nothing there answers `613`.

**Why the dial left the effect (2026-10-13, `1f74cc9b`):** the lane
parks with `io_park_on`, which wakes on the fd in `op.args[0]`. With
`tls_connect_raw(ip, …)` the first argument was a `String`, so no fd
existed and nothing woke. The correction is a signature change, not a
cast: the effect receives an **already-connected fd** and only handshakes
it. The same measurement had side effects: one owner for the dial
(`TCP.connect` already knows the non-blocking mode and the `EINPROGRESS`
park), and the 20-client TLS burst dropped from ~35.3 s to ~29.0 s
(D40). The twins pay one asymmetry for it. The C twin needs the fd
**blocking** for the handshake (the helper thread may block; measured
D39, where a non-blocking fd surfaced as `613`) and restores
`O_NONBLOCK` on the success path; a failure path closes the fd. The JS
twin parks instead. `612 dial failed` left the effect together with the
dial. The number stays in the code family: the message table of the C
twin maps it, and `tls_rt.js` documents it. The live handshake answers
`611 bad input` (fd/ALPN shape), and the transport answers with its own
dial code. A refused loopback dial measured `111` (ECONNREFUSED).

### One key share, four groups

The offer and the share are **two different extensions**.
`supported_groups` carries the four groups that the runtime serves:
x25519, P-256, P-384 and P-521, in the preference order of OpenSSL. A
capability probe filters that fixed table (`usable_groups`). x448 stays
outside the table on purpose, because the crypto of bun cannot compute
it. Thus every host offers the same four groups, also where the host can
compute more. The `key_share` extension carries exactly **one** group,
x25519. This choice follows the client policy of OpenSSL
(`tls_construct_ctos_key_share`: "For now, we just send one"), and the
code cites it in `lib/effs/tls_rt.js`, `build_client_hello`, the builder
that `send_hello` calls. Browsers send two shares. Nobody sends four.

Four shares would cost real bytes and real crypto for each handshake. A
share is the full public key of the peer (32 + 65 + 97 + 133 = 327 bytes
plus list headers, ~350 on the wire), and each one is a fresh
`generateKeyPairSync` (`make_share`). The server keeps exactly one of the
arriving shares and discards the rest. One share is 32 bytes and one
keygen for each handshake. The share for the group that the peer really
picks is generated **only then**, in `hello_retry` (`make_share(group)`),
never in advance.

HelloRetryRequest makes one share work, and it is a normal path, not an
edge case:

- **Client** (`hello_retry`): it takes the group from the bare
  KeyShareEntry of the HRR (and the cookie). It refuses a group that it
  does not offer and the same-group loop (a re-hello for ever). It builds
  the new share and restarts the transcript from the **synthetic
  message_hash** of ClientHello1 (RFC 8446 §4.4.1). CH1 in the transcript
  shows up only as a bad record MAC on the first encrypted flight of the
  peer. The ladder proves this half.
- **Server** (`send_hrr`): it asks for the first group that we serve and
  the peer lists, one time for each group (it refuses its own loop). The
  key_share extension carries the group **alone** (RFC 8446 §4.1.4). The
  server sends **no cookie**; the client parses a cookie and echoes it
  when a peer sends one. The HRR carries the cipher suite that the peer
  offered, and the transcript stays
  `[synthetic(CH1), HRR, CH2, ServerHello, …]`. This half was broken and
  is corrected (task-051 A6): `send_hrr` hashed a suite that was still
  `null` (a `TypeError` escaped `feed()` and killed the process), and
  `client_hello` refused each second ClientHello. Thus no peer could
  complete the retry.
- **The ladder pins both roles** (`tests/effs/tls-generic.sh`). The
  `group` rung negotiates each of the four groups in BOTH roles; the
  server role needs no HRR, because in TLS 1.3 the server adopts the
  share that the peer sent. The `hrr` rungs use a peer that is pinned to
  P-256, P-384 or P-521 and the x25519 control, and they now **assert**
  the value (`hrrs=1` for the three, `hrrs=0` for the control). The
  `hrr-server` rung drives openssl with a share for a group that we do
  not serve (`-groups ffdhe2048:x25519`) and requires the completed
  handshake after the re-share.

## The lab: what each piece of `tests/effs/` proves

| Piece | What it is | The claim it keeps alive |
|---|---|---|
| `parity.sh` | the twin lint above | each twin is generic, neutral about the loader and clean for syntax (26 passed, 3 known, 2026-10-15). The 3 known entries are the repeated `reuse tls_rt` loader that four files declare as debt. The five `generic` (bun:ffi) exceptions in the list no longer fire: the portable lane has no `ffi` require left |
| `twin_shared.bend` + `effs/twin_shared.js` | one file, two defs, shared state | a twin can group defs and hold module state one time (golden 26) |
| `tls_bench.bend` | the `test.bend` bench for the five defs | numbers before and after a lane swap (baseline `tls_connect_echo avg=5-7 ms`, 2026-10-12) |
| `bridge/` + `tls_bridge.sh` | the worker/SAB park bridge, measured end to end (6 counted outcomes; the adopt-under-bun leg is a NOTE) | why the bridge lost as the lane, and how `io_park_on` parks on a deadline without an fd |
| `tls-effects/` + `tls-effects.sh` | the **native-host `tls`** lane: `require("tls")`, Promise-returning effects, a runtime patch to dispatch them (32 assertions on this tree; 31 measured 2026-10-12, before `lib/effs` left `bun:ffi`; server legs SKIP on bun < 1.4.3). **JS only**: the package stages no `.c`, and its contract file imports the `.js` twins alone | the negative result that chose the portable pump, the 615 error taxonomy, and the rule "the listener is not probed with a throwaway connection" |
| `tls-generic/` + `tls-generic.sh` | the **portable pump** (the `tls_rt.js` of `lib/effs/`, staged copy): the interop ladder | client and server in TLS 1.3 **and** TLS 1.2, ALPN modes 0-3, four ECDHE groups pinned in both roles, HelloRetryRequest pinned in BOTH roles (`hrr` and `hrr-server`), the chain validity window of every certificate (hermetic `expired-chain`), 64 KB multi-record bulk in both directions, CBC at the padding boundary (hermetic), capability-filtered cipher tables, the five **effect** contracts, the installed drift check (sha256). ~90 rungs (95 assertion sites with egress; 83 offline, where the badssl block is one SKIP for each host), green in Node and Bun, and the same ladder against `BEND_EFFS_DIR=lib/effs` to prove the files that ship |
| `effs/tls_rt.js` (staged copy) | the runtime source of `lib/effs/tls_rt.js`, kept byte-identical by the drift rung | the header documents the scope (per RFC), the fail codes and the out-of-scope list |

The iron rule of the ladder: **the peer of each protocol rung is the
system `openssl`, never the TLS of the host**. One exception is
deliberate: the six hermetic `cbc-len` rungs use a Node `tls` server as
the peer, because the `tls` of bun refuses `ECDHE-RSA-AES128-SHA256`. The
client under test still runs on the named host. Each protocol assertion
has a rung in both directions: `bulk` reads what openssl sends, and
`bigsend` writes what openssl reassembles byte-for-byte. A test of our
effect against the same stack that it calls proves only that the host
agrees with itself. Two wire bugs (D21, D36) escaped earlier
self-consistent test pairs in that way. Network-dependent rungs (badssl:
self-signed, wrong.host, untrusted-root, expired, TLS 1.2/1.1/1.0) are
**SKIP** without egress, never silent passes.

### What the installation of the lane revealed

Until the ladder used the installed files, no gate in the repo drove
`lib/effs/`. The first real run of the installed effects found four bugs,
and each one got a covering golden:

| ID | Bug | Lesson |
|---|---|---|
| D44 | `sys.send/recv` return i64 (BigInt); `at + n` killed the process | the io_sys convention is `Number(...)`; the socket twins had it, and the new TLS twins initially did not |
| D45 | `feed()` required `Buffer`; effects hand `Uint8Array` | adopt as a **view** (`as_buf`) at the door; probes pass Buffers only because `net` hands Buffers |
| D46 | the server ALPN refused a client that offers nothing | an empty list answers "" (empty is better than a refusal to negotiate), and the ALPN extension is OMITTED, per RFC 7301 §3.2; golden `tests/io/tls_alpn_none.bend` (1111). A peer that DID send a list with no overlap is a different case: both lanes now answer `615` after the fatal alert (task-051 A7) |
| D47 | a test looped frames from `Nil{}` after the preface, and discarded what the same read brought | the portable lane delivers each application byte that is available for each read; the retired OpenSSL twin delivered one byte, and the tests were tuned to the lane |

### Fail codes on the TLS lane

| Code | Meaning | Owner today |
|---|---|---|
| `611` | bad input (port/fd/ALPN shape; the C twin also rejects a host with a NUL byte) | the effects, before any protocol work |
| `612` | dial failed | with the transport since `1f74cc9b`: the effect dials nothing. The dial answers the errno of `Base.TCP.connect` (a refused loopback dial measured `111` ECONNREFUSED), so `612` stays a documented family number in the tables of the twins |
| `613` | handshake failed | both lanes |
| `614` | verify failed | both lanes (chain, edges, hostname and badssl proof; the validity window of every certificate is checked, task-051 A8) |
| `615` | ALPN mismatch | **both roles, both lanes** (task-051 A7): a peer whose offered list has no overlap gets the fatal no_application_protocol alert 120 (RFC 7301 §3.2). The effects classify it by the OpenSSL reason code (235 when we refused, 1120 when the alert arrived), not as a generic `613`. `bend tests/io/tls_alpn_none.bend` prints `1111` on the interp/JS lane and on a `bend -o` binary. A peer that offers no ALPN at all still completes with no protocol selected |
| `616` | TLS error | the runtime of the effect (module unavailable, pump failure, fcntl on the C lane) |

DNS keeps its `601`-`605` codes and surfaces them **before any socket
exists**, so no handle can leak. Each fail code answers `Result`, never an
exception.

## The composite entries and the h2 world

`tls_connect(host, port)` (strict `h2`), `tls_connect_insecure`,
`tls_connect_noalpn[_insecure]` (WSS and Upgrade),
`tls_connect_any[_insecure]` (dual: it hands back the socket beside the
selected protocol) and, on the server, `tls_accept` (h2 preferred),
`tls_accept_alpn` (dual) and `tls_accept_http1`. All of them are
per-tool routes of the same `tls_dial*` composition and the ALPN modes
(`0` nothing, `1` h2 required by the client, `2` h2+http/1.1, `3`
http/1.1-only), served by the same raw defs. The server raw def accepts
offers `1`-`3` and rejects `0` with `611`. HTTP/2 (`lib/http2.bend`), the
HTTPS facade (`lib/https.bend`), HTTPX (`lib/httpx.bend`) and WSS
(`lib/wsm.bend`) are the customers; they inherit the two lanes and the
fail-code family without a change.

Proof at run time: the global goldens `tests/io/tls_connect_close.bend`
(111), `tls_alpn_dual.bend` (1), `wsm_loopback_tls.bend` (111),
`httpx_h1_upgrade.bend` (7) and `tests/io/httpx_h2_goaway.bend` (6) drive
the installed effects through the real runtime. These are the same
goldens that the repo gate (`check.sh --tests`) runs.
