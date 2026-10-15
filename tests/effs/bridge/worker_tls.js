// Phase 0 gate probe: does TLS work inside a worker, per runtime? The
// main thread parks on Atomics.wait while the worker dials and
// handshakes, which is the production shape (the worker owns its own
// socket: Bun cannot adopt an fd -- see tests/effs/tls_bridge.sh).
//
// Peer from the environment, so the gate can point it at a local
// openssl s_server with the test cert (no network):
//   P0_HOST P0_IP P0_PORT P0_VERIFY P0_ALPN
const { Worker } = require("worker_threads");

const HOST = process.env.P0_HOST || "127.0.0.1";
const IP = process.env.P0_IP || "127.0.0.1";
const PORT = Number(process.env.P0_PORT || 19443);
const VERIFY = process.env.P0_VERIFY === "1";
const ALPN = process.env.P0_ALPN || "http/1.1";
const TIMEOUT_MS = 8000;

const report = {
  runtime: process.versions.bun ? `bun ${process.versions.bun}`
    : `node ${process.versions.node}`,
};

const code = `
const { workerData } = require("worker_threads");
const net = require("net");
const tls = require("tls");
const ia = new Int32Array(workerData.sab);
const enc = new TextEncoder();
const publish = (patch) => {
  const b = enc.encode(JSON.stringify(patch));
  new Uint8Array(workerData.sab, 256, b.length).set(b);
  Atomics.store(ia, 1, b.length);
  Atomics.store(ia, 0, 1);
  Atomics.notify(ia, 0);
};
const t0 = performance.now();
let sock = null;
try {
  sock = net.connect({ host: workerData.ip, port: workerData.port });
} catch (e) {
  publish({ ok: false, error: "net.connect throw " + e.message });
}
if (sock !== null) {
  sock.once("error", (e) => publish({ ok: false, error: "dial " + e.message }));
  sock.once("connect", () => {
    const t1 = performance.now();
    try {
      // Bun 1.4.3 refuses an IP literal as servername (measured), and the
      // lib's contract is SNI = original host, dial = resolved IPv4.
      const opts = {
        socket: sock,
        ALPNProtocols: workerData.alpn,
        rejectUnauthorized: workerData.verify,
        ca: tls.rootCertificates,
      };
      if (!/^\d+\.\d+\.\d+\.\d+$/.test(workerData.host)) {
        opts.servername = workerData.host;
      }
      const sec = tls.connect(opts, () => {
        publish({
          ok: true,
          ms_dial: Math.round(t1 - t0),
          ms_handshake: Math.round(performance.now() - t1),
          alpn: sec.alpnProtocol ?? null,
          authorized: sec.authorized,
          protocol: sec.getProtocol(),
        });
      });
      sec.on("error", (e) => publish({ ok: false, error: "tls " + e.message }));
    } catch (e) {
      publish({ ok: false, error: "tls.connect throw " + e.message });
    }
  });
}
setTimeout(() => publish({ ok: false, error: "worker timeout" }), ${TIMEOUT_MS});
`;

const sab = new SharedArrayBuffer(65536);
const ia = new Int32Array(sab);
let worker = null;
try {
  worker = new Worker(code, {
    eval: true,
    workerData: {
      sab: sab,
      host: HOST,
      ip: IP,
      port: PORT,
      verify: VERIFY,
      alpn: [ALPN],
    },
  });
  report.worker_eval = true;
} catch (e) {
  report.worker_eval = `throw ${e.message}`;
}

if (worker) {
  const t0 = performance.now();
  Atomics.wait(ia, 0, 0, TIMEOUT_MS + 2000);
  report.main_blocked_ms = Math.round(performance.now() - t0);
  const len = Atomics.load(ia, 1);
  if (len > 0) {
    Object.assign(report, JSON.parse(
      new TextDecoder().decode(new Uint8Array(sab, 256, len))));
  } else {
    report.no_answer = true;
  }
  worker.terminate();
}
console.log(JSON.stringify(report));
