// scratch/tls_probe.js — <host> <port> <alpn 0..3> [verify 0..1]
//
// Drives tls_connect_raw from ../effs/tls_connect.js against a reference
// peer and prints one line:
//
//   OK ver=1.3 alpn="h2" auth=1 cipher=aes-128-gcm | HTTP/1.1 200 OK
//   FAIL <code> <text>
//
// `host` is both the address dialled and the SNI, so a loopback ladder
// runs with an IP (no SNI) and a badssl host runs with its name (SNI
// plus hostname verification). `verify` is explicit because the ladder
// has two legitimate regimes: a local self-signed peer is 0, the public
// internet is 1.
//
// P0_REQUEST   request head lines to send once the handshake is done;
//              the probe appends the CRLFCRLF terminator, because a
//              shell cannot pass a trailing blank line through an
//              environment variable (command substitution strips it).
//              openssl s_server -www answers nothing until it gets one.
// P0_TIMEOUT_MS  bound on the whole run (default 15000).
//
// Exit status: 0 the handshake completed and the application data came
// back, 1 the effect refused, 2 usage, 3 nothing happened in time.

const h = require("./eff_harness.js");

const TIMEOUT_MS = Number(process.env.P0_TIMEOUT_MS || 15000);
const HEAD = process.env.P0_REQUEST || "";
const REQUEST = HEAD ? HEAD + "\r\n\r\n" : "";

const host = process.argv[2];
const port = Number(process.argv[3]);
const alpn = Number(process.argv[4] === undefined ? 3 : process.argv[4]);
const verify = process.argv[5] === undefined ? 1 : Number(process.argv[5]);

// A single exit path, so the watchdog and the normal end cannot both
// write a line.
function stop(code) {
  process.exit(code);
}

// Reads from `conn` until the peer sends a blank line, closes, or the
// deadline passes. Returns the bytes gathered so far.
async function read_reply(conn, recv, deadline) {
  let text = "";
  while (Date.now() < deadline) {
    const res = h.result_of(await recv(conn, 65536, null));
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

// The handshake line: what the gate asserts is here.
function report_ok(conn, selected, reply) {
  const parts = ["OK ver=" + h.version_tag(conn.socket),
    "alpn=" + JSON.stringify(selected),
    "auth=" + (conn.authorized ? 1 : 0),
    "cipher=" + h.cipher_tag(conn.socket)];
  if (reply) parts.push("| " + reply.split("\r\n")[0].trim());
  console.log(parts.join(" "));
}

async function main() {
  const deadline = Date.now() + TIMEOUT_MS;
  if (!host || !Number.isInteger(port) || port < 1 || alpn < 0 || alpn > 3) {
    console.log("FAIL 611 usage: tls_probe.js <host> <port> <alpn> [verify]");
    return 2;
  }

  const connect = h.load_effect("tls_connect.js", "tls_connect_raw");
  const send = h.load_effect("tls_send_bytes.js", "tls_send_bytes");
  const recv = h.load_effect("tls_recv_bytes.js", "tls_recv_bytes");
  const close = h.load_effect("tls_close.js", "tls_close");

  const res = await connect(host, host, port, verify, alpn, null);
  if (res.$ !== "Done") {
    console.log("FAIL " + res.error.fst + " " + res.error.snd);
    return 1;
  }
  const conn = res.value.fst;
  const selected = res.value.snd;
  try {
    let reply = "";
    if (REQUEST) {
      const sent = h.result_of(await send(conn,
        h.bytes_to_list(Buffer.from(REQUEST, "latin1")), null));
      if (sent.$ !== "Done") {
        console.log("FAIL " + sent.error.fst + " send refused");
        return 1;
      }
      reply = await read_reply(conn, recv, deadline);
    }
    report_ok(conn, selected, reply);
    return 0;
  } finally {
    await close(conn);
  }
}

setTimeout(() => {
  console.log("FAIL 613 timeout after " + TIMEOUT_MS + "ms");
  stop(3);
}, TIMEOUT_MS).unref?.();

main().then((code) => stop(code)).catch((error) => {
  console.log("ERR " + (error && error.message ? error.message : error));
  stop(2);
});