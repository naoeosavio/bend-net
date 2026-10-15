// scratch/tls_server_probe.js — <cert> <key> <port> [offer 1..3]
//
// Drives tls_accept_raw from ../effs/tls_accept.js on a plain TCP
// listener, so openssl s_client -- or the other host's client probe --
// can peer against it. Prints one line per completed handshake:
//
//   OK ver=1.3 alpn="h2"
//   FAIL <code> <text>
//
// Each accepted session answers whatever request arrives with a short
// 200 and then closes, so the peer's exit status means "the answer came
// back", not just "the handshake did not break" -- a half-open handshake
// would pass a weaker assertion.
//
// P0_TIMEOUT_MS  bound on each handshake (default 15000).
//
// Exit status: 0 when killed after serving, 1 the effect refused, 2 the
// listener failed to bind, 3 a handshake never completed.

const net = require("net");
const h = require("./eff_harness.js");

const TIMEOUT_MS = Number(process.env.P0_TIMEOUT_MS || 15000);
const ANSWER = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";

const cert = process.argv[2];
const key = process.argv[3];
const port = Number(process.argv[4]);
const offer = Number(process.argv[5] === undefined ? 2 : process.argv[5]);

// Reads the peer's request head, so the answer is only sent to a peer
// that actually spoke. A peer that hangs up early ends the read.
async function read_request(conn, recv, deadline) {
  let text = "";
  while (Date.now() < deadline) {
    const res = h.result_of(await recv(conn, 4096, null));
    if (res.$ !== "Done") {
      throw new Error("recv failed with " + res.error.fst);
    }
    const bytes = h.list_to_bytes(res.value);
    if (bytes.length === 0) break;
    text += Buffer.from(bytes).toString("latin1");
    if (h.has_head_end(text)) break;
  }
  return text;
}

// Serves one accepted session: read the request, answer it, close.
async function serve(conn, recv, send, close) {
  try {
    await read_request(conn, recv, Date.now() + TIMEOUT_MS);
    await send(conn, h.bytes_to_list(Buffer.from(ANSWER, "latin1")), null);
  } finally {
    await close(conn);
  }
}

async function main() {
  if (!cert || !key || !Number.isInteger(port) || offer < 1 || offer > 3) {
    console.log("FAIL 611 usage: tls_server_probe.js <cert> <key> <port> " +
      "[offer]");
    return 2;
  }

  const accept = h.load_effect("tls_accept.js", "tls_accept_raw");
  const send = h.load_effect("tls_send_bytes.js", "tls_send_bytes");
  const recv = h.load_effect("tls_recv_bytes.js", "tls_recv_bytes");
  const close = h.load_effect("tls_close.js", "tls_close");

  const listener = net.createServer();
  listener.on("error", (error) => {
    console.log("ERR " + (error.code || error.message));
    process.exit(2);
  });
  await new Promise((done) => listener.listen(port, "127.0.0.1", done));
  console.log("up " + listener.address().port);

  // One accept per connection: the effect takes a single `connection`
  // event, so the loop is what makes the probe serve more than one peer.
  for (;;) {
    const res = await Promise.race([
      accept(listener, cert, key, offer, null),
      new Promise((lost) => setTimeout(() => lost("timeout"), TIMEOUT_MS)
        .unref?.()),
    ]);
    if (res === "timeout") {
      console.log("FAIL 613 handshake never completed after " +
        TIMEOUT_MS + "ms");
      return 3;
    }
    if (res.snd.$ !== "Done") {
      console.log("FAIL " + res.snd.error.fst + " " + res.snd.error.snd);
      continue;
    }
    const conn = res.snd.value.fst;
    console.log("OK ver=" + h.version_tag(conn.socket) +
      " alpn=" + JSON.stringify(res.snd.value.snd));
    await serve(conn, recv, send, close);
  }
}

main().then((code) => {
  if (code !== undefined) process.exit(code);
}).catch((error) => {
  console.log("ERR " + (error && error.message ? error.message : error));
  process.exit(2);
});

process.on("SIGTERM", () => process.exit(0));
process.on("SIGINT", () => process.exit(0));