// scratch/tls_probe.js — <host> <port> <alpn 0..3> [verify 0..1]
//
// Drives the portable client against a reference peer. Prints one line:
//   OK ver="1.3" alpn="h2" aes-128-gcm/sha256 | HTTP/1.1 200 OK
//   FAIL <code> <text>
// Exit status: 0 on a completed handshake with application data, 1 on a
// pump failure, 2 on a socket error, 3 on timeout.
const net = require("net");
const rt = require("./rt_path.js");

const host = process.argv[2];
const port = Number(process.argv[3]);
const mode = Number(process.argv[4] || 3);
const verify = process.argv[5] === undefined ? 1 : Number(process.argv[5]);
const TIMEOUT_MS = Number(process.env.P0_TIMEOUT_MS || 15000);

if (!host || !Number.isInteger(port) || !(mode >= 0 && mode <= 3)) {
  console.log("FAIL 611 usage: tls_probe.js <host> <port> <alpn> [verify]");
  process.exit(1);
}

const pump = rt.make_client(host, verify, mode);
const REQUEST = process.env.P0_REQUEST;
let body = "";
let settled = false;
let has_sent_request = false;

const finish = (code) => {
  if (settled) {
    return;
  }
  settled = true;
  try { sock.destroy(); } catch (e) {}
  process.exit(code);
};

const sock = net.connect(port, host, () => {
  const b = pump.drain();
  if (b !== null) {
    sock.write(b);
  }
});

sock.on("data", (d) => {
  pump.feed(d);
  if (pump.fail !== null) {
    console.log("FAIL", pump.fail.code, pump.fail.text);
    finish(1);
    return;
  }
  const b = pump.drain();
  if (b !== null) {
    sock.write(b);
  }
  const app = pump.take_app(65536);
  if (app !== null) {
    body += app.toString("latin1");
  }
  if (pump.done && !REQUEST) {
    // No request to make: the handshake is the whole test.
    console.log("OK ver=" + pump.ver,
      "alpn=" + JSON.stringify(pump.alpn),
      "group=" + rt.group_name(pump.share.group),
      pump.suite.name + "/" + pump.suite.hash,
      "| (handshake only)");
    finish(0);
    return;
  }
  if (pump.done && REQUEST && !has_sent_request) {
    // `openssl s_server -www` answers only after a request, so send one
    // and keep reading. Exactly once: the data handler fires again for
    // the reply, and re-sending here would loop.
    has_sent_request = true;
    pump.seal_app(Buffer.from(REQUEST, "ascii"));
    const out = pump.drain();
    if (out !== null) {
      sock.write(out);
    }
  }
  if (pump.done && body.length > 0) {
    console.log("OK ver=" + pump.ver,
      "alpn=" + JSON.stringify(pump.alpn),
      "group=" + rt.group_name(pump.share.group),
      pump.suite.name + "/" + pump.suite.hash,
      "|", body.split("\r\n")[0].trim());
    finish(0);
  }
});

sock.on("error", (e) => {
  console.log("ERR", e.code || e.message);
  finish(2);
});

setTimeout(() => {
  console.log("TIMEOUT done=" + pump.done);
  finish(3);
}, TIMEOUT_MS).unref?.();