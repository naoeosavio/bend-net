// scratch/hrr_probe.js — <host> <port>
//
// Drives the HelloRetryRequest path and reports what happened, so the
// gate can tell a completed handshake from a refusal.
//
// With one key share per ClientHello (the OpenSSL policy), a server whose
// group order differs answers with an HRR instead of a ServerHello. That
// makes the retry a NORMAL path, and the thing worth asserting is the
// transcript: RFC 8446 s4.4.1 replaces ClientHello1 with a synthetic
// message_hash, so the transcript must restart from a message of type
// 254 rather than carrying ClientHello1 forward. Getting that wrong
// still produces a well-formed handshake attempt that fails as a bad
// record MAC on the peer's first encrypted flight.
//
// Prints:
//   OK hrrs=<n> done=true transcript0=<type> alpn=<x>
//
// Exit status: 0 when the handshake completed, 1 otherwise.
const net = require("net");
const rt = require("./rt_path.js");

const host = process.argv[2];
const port = Number(process.argv[3]);
const TIMEOUT_MS = Number(process.env.P0_TIMEOUT_MS || 20000);

if (!host || !Number.isInteger(port)) {
  console.log("FAIL 611 usage: hrr_probe.js <host> <port>");
  process.exit(1);
}

const pump = rt.make_client(host, false, 1);
let hrrs = 0;

const orig_retry = pump.hello_retry.bind(pump);
pump.hello_retry = function (m) {
  hrrs += 1;
  return orig_retry(m);
};

const finish = (code) => {
  try { sock.destroy(); } catch (e) {}
  process.exit(code);
};

const sock = net.connect(port, host, () => {
  const first = pump.drain();
  if (first !== null) {
    sock.write(first);
  }
});

sock.on("data", (d) => {
  pump.feed(d);
  if (pump.fail !== null) {
    console.log("FAIL " + pump.fail.code + " " + pump.fail.text
      + " hrrs=" + hrrs);
    finish(1);
    return;
  }
  const out = pump.drain();
  if (out !== null) {
    sock.write(out);
  }
  if (pump.done) {
    const head = pump.transcript.length > 0 ? pump.transcript[0][0] : -1;
    console.log("OK hrrs=" + hrrs + " done=true transcript0=" + head
      + " alpn=" + JSON.stringify(pump.alpn));
    finish(0);
  }
});

sock.on("error", (e) => {
  console.log("ERR " + (e.code || e.message) + " hrrs=" + hrrs);
  finish(1);
});

setTimeout(() => {
  console.log("TIMEOUT hrrs=" + hrrs + " done=" + pump.done + " fail="
    + JSON.stringify(pump.fail));
  finish(1);
}, TIMEOUT_MS).unref?.();