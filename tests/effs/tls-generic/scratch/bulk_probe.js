// scratch/bulk_probe.js — <host> <port> <path>
//
// Application-data path, not handshake: sends one HTTP request and counts
// every decrypted byte until the peer's close_notify. `openssl s_server
// -WWW` serves a real file, so the caller can ask for one larger than the
// 2^14 record ceiling -- the case a handshake-only assertion cannot see,
// and the case a stream that silently drops the tail WOULD see.
//
// Prints:
//   OK appBytes=<n> records=<n> closed=true ver=<v> suite=<name>
//
// Exit status: 0 on close_notify, 1 on a pump failure, 2 on a socket
// error, 3 on timeout.
const net = require("net");
const rt = require("./rt_path.js");

const host = process.argv[2];
const port = Number(process.argv[3]);
const TIMEOUT_MS = Number(process.env.P0_TIMEOUT_MS || 20000);
const PATH = process.argv[4] || "/";
// take_app hands back at most this much per call and keeps the rest, so
// the drain loop below is what makes the total independent of how the
// bytes were split across TCP reads.
const CHUNK_MAX = 65536;

if (!host || !Number.isInteger(port)) {
  console.log("FAIL 611 usage: bulk_probe.js <host> <port> [path]");
  process.exit(1);
}

const REQUEST = Buffer.from("GET " + PATH + " HTTP/1.0\r\n\r\n");
const pump = rt.make_client(host, false, 1);
let app_bytes = 0;
let is_sent = false;

const finish = (code) => {
  try { sock.destroy(); } catch (e) {}
  process.exit(code);
};

// Take everything the record layer has buffered. The return value is
// null once the buffer is empty, which is the loop's exit condition.
const drain_app = () => {
  let total = 0;
  let app = pump.take_app(CHUNK_MAX);
  while (app !== null) {
    total += app.length;
    app = pump.take_app(CHUNK_MAX);
  }
  return total;
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
    console.log("FAIL", pump.fail.code, pump.fail.text);
    finish(1);
    return;
  }
  const out = pump.drain();
  if (out !== null) {
    sock.write(out);
  }
  // One request, once: the handshake is done and the peer is waiting.
  if (pump.done && !is_sent) {
    is_sent = true;
    pump.seal_app(REQUEST);
    const req = pump.drain();
    if (req !== null) {
      sock.write(req);
    }
  }
  app_bytes += drain_app();
  // close_notify is the orderly end of the stream; a bare TCP EOF would
  // leave pump.closed false, and that difference is worth asserting.
  // The final drain_app() above runs first, so bytes that arrived in the
  // same read as the alert are counted and not left in the buffer.
  if (pump.closed) {
    // records= is MEASURED by the record layer, not derived from the
    // byte count. Deriving it would assume records are packed to the
    // ceiling, which is the very thing the caller wants to know.
    console.log("OK appBytes=" + app_bytes + " records=" + pump.app_records
      + " closed=true ver=" + pump.ver + " suite=" + pump.suite.name);
    finish(0);
  }
});

sock.on("error", (e) => {
  console.log("ERR", e.code || e.message, "appBytes=" + app_bytes);
  finish(2);
});

setTimeout(() => {
  console.log("TIMEOUT appBytes=" + app_bytes + " closed=" + pump.closed);
  finish(3);
}, TIMEOUT_MS).unref?.();