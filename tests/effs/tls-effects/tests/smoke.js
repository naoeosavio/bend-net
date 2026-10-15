// tests/smoke.js — the five effects, end to end, in one process, on
// whichever host runs it (node or bun).
//
// What it proves, in order:
//   1. the client effect handshakes against the server effect, with ALPN
//      http/1.1 (the `3` policy of the documented contract);
//   2. application bytes cross in both directions through tls_send_bytes
//      and tls_recv_bytes;
//   3. the refusals keep their codes: 611 for a handle that is not a TLS
//      connection, and 22 for a byte past 255, which must be caught
//      before any byte leaves;
//   4. tls_close shuts both ends down.
//
// The certificate is generated per run and deleted with the temporary
// directory, so the test never depends on a checked-in cert that expires
// on a schedule nobody remembers. Verification is off (verify = 0)
// because the cert is self-signed: the ladder in ../tls-effects.sh is
// where a verified chain is asserted.
//
// A host that cannot serve inbound TLS from a socket it did not create
// (bun 1.2.15 -- see the task's D30) cannot pass step 1. The watchdog
// below says so instead of hanging.
const cp = require("child_process");
const fs = require("fs");
const net = require("net");
const os = require("os");
const path = require("path");

const h = require("../scratch/eff_harness.js");

const TIMEOUT_MS = Number(process.env.P0_TIMEOUT_MS || 30000);
const ALPN_POLICY = 3;
const HEAD = "ping";
const ANSWER = "pong";

// Where the run got to, so a watchdog can name the step instead of
// printing nothing.
let stage = "start";

function enter(step) {
  stage = step;
}

// Reads one message off `conn`, bounded by the deadline. The effects
// hand the socket back beside the Result, so both shapes go through
// result_of.
async function recv_message(conn, recv, deadline) {
  while (Date.now() < deadline) {
    const res = await recv(conn, 1024, null);
    const result = h.result_of(res);
    if (result.$ !== "Done") {
      throw new Error("recv failed with " + result.error.fst);
    }
    const bytes = h.list_to_bytes(result.value);
    if (bytes.length) return Buffer.from(bytes).toString("utf8");
  }
  return "";
}

// The refusals the defs promise. Each one is checked against a live
// connection or a value that cannot be one, never against a mock.
async function check_refusals(conn, send, recv) {
  const bad_send = h.result_of(await send({ $: "NotATlsConn" },
    h.bytes_to_list(Buffer.from("x")), null));
  if (bad_send.$ !== "Fail" || bad_send.error.fst !== 611) {
    throw new Error("send on a foreign handle must answer 611, got " +
      JSON.stringify(bad_send));
  }
  const bad_recv = h.result_of(await recv({ $: "NotATlsConn" }, 16, null));
  if (bad_recv.$ !== "Fail" || bad_recv.error.fst !== 611) {
    throw new Error("recv on a foreign handle must answer 611, got " +
      JSON.stringify(bad_recv));
  }
  // A byte past 255 is EINVAL (22) and must be caught before the write,
  // so the connection stays usable afterwards: the round trip below
  // proves it by sending one more message.
  const too_big = { $: "Con", head: 256, tail: { $: "Nil" } };
  const overflow = h.result_of(await send(conn, too_big, null));
  if (overflow.$ !== "Fail" || overflow.error.fst !== 22) {
    throw new Error("a byte past 255 must answer 22, got " +
      JSON.stringify(overflow));
  }
}

async function main() {
  enter("cert");
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bend-tls-effects-"));
  const cert = path.join(temp, "cert.pem");
  const key = path.join(temp, "key.pem");
  cp.execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost"],
    { stdio: "ignore" });

  const connect = h.load_effect("tls_connect.js", "tls_connect_raw");
  const accept = h.load_effect("tls_accept.js", "tls_accept_raw");
  const send = h.load_effect("tls_send_bytes.js", "tls_send_bytes");
  const recv = h.load_effect("tls_recv_bytes.js", "tls_recv_bytes");
  const close = h.load_effect("tls_close.js", "tls_close");

  const deadline = Date.now() + TIMEOUT_MS;
  const server = net.createServer();
  let client = null;
  let server_side = null;
  try {
    enter("listen");
    await new Promise((done, refused) => {
      server.listen(0, "127.0.0.1", done).once("error", refused);
    });

    enter("accept+connect");
    // The accept effect waits for the listener's connection event, so it
    // starts first; the client effect then completes the handshake.
    const accepted = accept(server, cert, key, ALPN_POLICY, null);
    const port = server.address().port;
    const dialed = await connect("127.0.0.1", "localhost", port, 0,
      ALPN_POLICY, null);
    if (dialed.$ !== "Done") {
      throw new Error("client refused with " + dialed.error.fst + " " +
        dialed.error.snd);
    }
    client = dialed.value.fst;
    const served = await accepted;
    if (served.snd.$ !== "Done") {
      throw new Error("server refused with " + served.snd.error.fst + " " +
        served.snd.error.snd);
    }
    server_side = served.snd.value.fst;
    const alpn = [dialed.value.snd, served.snd.value.snd];
    if (alpn[0] !== "http/1.1" || alpn[1] !== "http/1.1") {
      throw new Error("ALPN http/1.1 expected, got " + JSON.stringify(alpn));
    }

    enter("echo");
    await send(client, h.bytes_to_list(Buffer.from(HEAD)), null);
    if (await recv_message(server_side, recv, deadline) !== HEAD) {
      throw new Error("the server did not read the request");
    }
    await send(server_side, h.bytes_to_list(Buffer.from(ANSWER)), null);
    if (await recv_message(client, recv, deadline) !== ANSWER) {
      throw new Error("the client did not read the answer");
    }

    enter("refusals");
    await check_refusals(client, send, recv);
    await send(client, h.bytes_to_list(Buffer.from(HEAD)), null);
    if (await recv_message(server_side, recv, deadline) !== HEAD) {
      throw new Error("the connection did not survive a refused send");
    }

    enter("close");
    await close(client);
    await close(server_side);
    client = null;
    server_side = null;
    console.log("PASS: " + h.host_tag() + " TLS handshake, ALPN, " +
      "bidirectional send/recv, refusal codes, close");
  } finally {
    if (client) await close(client);
    if (server_side) await close(server_side);
    await new Promise((done) => {
      if (server.listening) server.close(done); else done();
    });
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

setTimeout(() => {
  console.error("FAIL: stuck at the " + stage + " step after " + TIMEOUT_MS +
    "ms (" + h.host_tag() + ")");
  process.exit(1);
}, TIMEOUT_MS).unref?.();

main().catch((error) => {
  console.error("FAIL at the " + stage + " step: " +
    (error && error.message ? error.message : error));
  process.exitCode = 1;
});