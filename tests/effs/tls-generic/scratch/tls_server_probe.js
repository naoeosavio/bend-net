// scratch/tls_server_probe.js — <cert> <key> <port> [offer 1..3]
//
// Drives the portable server on a loopback TCP socket, so `openssl
// s_client` (or a Node/Bun native client) can peer against it. Prints one
// line per completed handshake:
//
//   OK ver="1.3" alpn="h2" aes-128-gcm/sha256
//   FAIL <code> <text>
//
// Exit status: 0 when the peer disconnected cleanly after a completed
// handshake, 1 on a pump failure, 2 on a bind error.
//
// Note the require path: rt_path.js picks the runtime to load. The default
// is this package's own effs/tls_rt.js; BEND_EFFS_DIR points at another
// copy, which is how the gate runs this probe against lib/effs/tls_rt.js
// -- the one task-046-tls-js-lane-into-lib installed, the file that ships.
const net = require("net");
const rt = require("./rt_path.js");

const cert = process.argv[2];
const key = process.argv[3];
const port = Number(process.argv[4]);
const offer = Number(process.argv[5] || 2);
const P0_CLOSE_MS = Number(process.env.P0_CLOSE_MS || 200);
// Response size. The default two bytes are enough for a handshake-only
// peer, but they fit in a single record and so say nothing about how the
// send path frames a large write. A caller that wants openssl to check
// our framing raises this past the 2^14 record ceiling.
const P0_REPLY_BYTES = Number(process.env.P0_REPLY_BYTES || 0);

// The same distinctive bytes the probes use, so a reorder or a duplicated
// chunk cannot hide behind a byte count that happens to match.
const body_of = (n) => {
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i += 1) b[i] = (i * 31 + (i >> 8) * 7) & 255;
  return b;
};

const DEFAULT_REPLY = Buffer.from(
  "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");

if (!cert || !key || !Number.isInteger(port)) {
  console.log("FAIL 611 usage: tls_server_probe.js <cert> <key> <port> [offer]");
  process.exit(1);
}

const handshake = (sock) => {
  let pump;
  try {
    pump = rt.make_server(cert, key, offer);
  } catch (e) {
    console.log("FAIL 613 " + (e && e.message ? e.message : "load failed"));
    sock.destroy();
    return;
  }
  let is_reported = false;
  sock.on("data", (d) => {
    pump.feed(d);
    if (pump.fail !== null) {
      console.log("FAIL", pump.fail.code, pump.fail.text);
      sock.destroy();
      return;
    }
    const b = pump.drain();
    if (b !== null) {
      sock.write(b);
    }
    if (pump.done && !is_reported) {
      is_reported = true;
      // Answer, then shut down in order: close_notify inside the record
      // layer first, so the peer sees a clean TLS close instead of a
      // bare TCP EOF (openssl reports that as "unexpected eof" and
      // exits non-zero, which would make a passing handshake look
      // like a failure).
      pump.seal_app(P0_REPLY_BYTES > 0
        ? body_of(P0_REPLY_BYTES)
        : DEFAULT_REPLY);
      pump.shutdown();
      const reply = pump.drain();
      if (reply !== null) {
        sock.write(reply, () => {
          // Then the transport: `openssl s_client` waits for EOF, so a
          // probe that never closes makes the peer hang on its own
          // timeout. The real close path is tls_close, not this.
          setTimeout(() => sock.end(), P0_CLOSE_MS);
        });
      }
      console.log("OK ver=" + pump.ver,
        "alpn=" + JSON.stringify(pump.alpn),
        "group=" + rt.group_name(pump.eph.group),
        pump.suite.name + "/" + pump.suite.hash);
    }
  });
  sock.on("error", () => { sock.destroy(); });
};

const listener = net.createServer((sock) => handshake(sock));

listener.on("error", (e) => {
  console.log("ERR " + (e.code || e.message));
  process.exit(2);
});

listener.listen(port, "127.0.0.1", () => console.log("up"));

process.on("SIGTERM", () => process.exit(0));
process.on("SIGINT", () => process.exit(0));