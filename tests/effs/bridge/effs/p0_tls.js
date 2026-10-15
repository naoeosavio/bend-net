// Phase 0 gate twin: TLS entirely inside a worker (it dials its own
// TCP socket, because Bun cannot adopt an fd -- measured), with the main
// thread waiting on a SharedArrayBuffer. Two wait modes: mode 0 parks on
// a 1 ms deadline (cooperative, io_park_on), mode 1 blocks the main
// thread on Atomics.wait. Answers the total milliseconds, or 9000 + the
// failure code; the per op numbers go to stderr as one JSON line.
//
// Scratch (a gate copy lands in tests/effs/): it exists to pick the
// bridge with a number, not to ship.
const P0_STATE = 0;
const P0_OP = 1;
const P0_PORT = 2;
const P0_FLAGS = 3;
const P0_CODE = 4;
const P0_MS = 5;
const P0_ALPN = 6;
const P0_AUTH = 7;
const P0_LEN = 8;
const P0_SNI_LEN = 9;
const P0_IP_LEN = 10;
const P0_DONE_SEQ = 12;
const P0_SNI_AT = 256;
const P0_IP_AT = 512;
const P0_PAY_AT = 1024;
const P0_TIMEOUT_MS = 8000;
const P0_CONNECT = 1;
const P0_SEND = 2;
const P0_RECV = 3;
const P0_CLOSE = 4;

const P0_WORKER = `
const { parentPort, workerData } = require("worker_threads");
const net = require("net");
const tls = require("tls");

const ia = new Int32Array(workerData.sab);
const dec = new TextDecoder();
const load = (w) => Atomics.load(ia, w);
const store = (w, v) => Atomics.store(ia, w, v);
const bytes_at = (at, n) => new Uint8Array(workerData.sab, at, n);
store(15, 1);
Atomics.notify(ia, 15);
store(16, 1);
const finish = (code) => {
  store(${P0_CODE}, code);
  store(${P0_STATE}, 2);
  Atomics.add(ia, ${P0_DONE_SEQ}, 1);
  Atomics.notify(ia, ${P0_DONE_SEQ});
};
const sni = () => dec.decode(bytes_at(${P0_SNI_AT}, load(${P0_SNI_LEN})));
const ip = () => dec.decode(bytes_at(${P0_IP_AT}, load(${P0_IP_LEN})));
let session = null;

const op_connect = () => {
  const flags = load(${P0_FLAGS});
  const mode = flags & 3;
  const offer = mode === 1 ? ["h2"]
    : mode === 2 ? ["h2", "http/1.1"]
      : mode === 3 ? ["http/1.1"] : [];
  const t0 = performance.now();
  let sock = null;
  try {
    sock = net.connect({ host: ip(), port: load(${P0_PORT}) });
  } catch (e) {
    finish(10);
    return;
  }
  sock.once("error", () => finish(12));
  sock.once("connect", () => {
    try {
      session = tls.connect({
        socket: sock,
        servername: sni(),
        ALPNProtocols: offer,
        rejectUnauthorized: (flags & 4) !== 0,
        ca: tls.rootCertificates,
      }, () => {
        store(${P0_MS}, Math.round(performance.now() - t0));
        store(${P0_ALPN}, session.alpnProtocol === "h2" ? 1
          : session.alpnProtocol === "http/1.1" ? 2 : 0);
        store(${P0_AUTH}, session.authorized ? 1 : 0);
        finish(0);
      });
    } catch (e) {
      finish(11);
      return;
    }
    session.on("error", () => finish(12));
    session.setTimeout(${P0_TIMEOUT_MS}, () => finish(13));
  });
};

const op_send = () => {
  const n = load(${P0_LEN});
  const text = dec.decode(bytes_at(${P0_PAY_AT}, n));
  const t0 = performance.now();
  session.write(text, () => {
    store(${P0_MS}, Math.round(performance.now() - t0));
    finish(0);
  });
};

const op_recv = () => {
  const max = load(${P0_LEN});
  const t0 = performance.now();
  session.once("data", (b) => {
    const n = Math.min(b.length, max);
    bytes_at(${P0_PAY_AT}, n).set(b.subarray(0, n));
    store(${P0_LEN}, n);
    store(${P0_MS}, Math.round(performance.now() - t0));
    finish(0);
  });
};

const op_close = () => {
  try {
    if (session !== null) {
      session.end();
      session.destroy();
      session = null;
    }
  } catch (e) {
    // best effort: close never fails the caller
  }
  finish(0);
};

const on_request = (msg) => {
  if (msg !== "op") {
    return;
  }
  store(${P0_STATE}, 3);
  const op = load(${P0_OP});
  if (op === ${P0_CONNECT}) {
    op_connect();
  } else if (op === ${P0_SEND}) {
    op_send();
  } else if (op === ${P0_RECV}) {
    op_recv();
  } else if (op === ${P0_CLOSE}) {
    op_close();
  } else {
    finish(14);
  }
};

parentPort.on("message", on_request);
`;

// The bridge is one worker per process, created on first use and kept in
// a global slot; the worker answers one op at a time.
function p0_bridge() {
  if (globalThis.P0_BRIDGE === undefined) {
    let made = null;
    try {
      const threads = require("worker_threads");
      const sab = new SharedArrayBuffer(65536);
      const worker = new threads.Worker(P0_WORKER, {
        eval: true,
        workerData: { sab: sab },
      });
      // The worker publishes a hello word before it can take work:
      // postMessage before the listener exists would race.
      Atomics.wait(new Int32Array(sab), 15, 0, 2000);
      worker.on("error", (e) => console.error("p0 worker error " + e.message));
      made = {
        ia: new Int32Array(sab),
        sab: sab,
        worker: worker,
        enc: new TextEncoder(),
        dec: new TextDecoder(),
      };
    } catch (e) {
      made = null;
    }
    globalThis.P0_BRIDGE = made;
  }
  return globalThis.P0_BRIDGE;
}

// Writes the request (op plus its parameters) and hands it to the
// worker. The worker answers by bumping DONE_SEQ, which is what the
// parked main thread watches.
function p0_request(b, op, len, text) {
  const b8 = b.enc.encode(text);
  new Uint8Array(b.sab, P0_PAY_AT, b8.length).set(b8);
  Atomics.store(b.ia, P0_LEN, len === undefined ? b8.length : len);
  Atomics.store(b.ia, P0_OP, op);
  Atomics.store(b.ia, P0_STATE, 1);
  b.worker.postMessage("op");
}

// Waits for the completion sequence to move past `done`: mode 1 blocks
// the main thread, mode 0 parks on a 1 ms deadline and lets the loop
// serve every other computation.
function p0_wait(b, mode, done, k, next) {
  if (mode === 1) {
    while (Atomics.load(b.ia, P0_DONE_SEQ) === done) {
      Atomics.wait(b.ia, P0_DONE_SEQ, done, P0_TIMEOUT_MS);
    }
    return next();
  }
  const go = () => {
    if (Atomics.load(b.ia, P0_DONE_SEQ) === done) {
      io_park_on(undefined, false, k, go, performance.now() + 1);
      return undefined;
    }
    return next();
  };
  return go();
}

function p0_tls(ip, sni, port, mode, req, k) {
  const b = p0_bridge();
  // A bare U32 effect answers the number itself; io_done is for
  // Result-shaped effects (measured: io_done here reads as 0).
  const bad = (code) => 9000 + code;
  if (b === null) {
    return bad(20);
  }
  port = Number(port);
  mode = Number(mode);
  const t0 = performance.now();
  const marks = [];
  let got = "";
  // One op at a time: request, wait for DONE_SEQ, read the answer, step.
  // i = 0 connect, 1 send, 2 recv, 3 close, 4 report.
  const step = (i) => {
    const code = Atomics.load(b.ia, P0_CODE);
    marks.push(Math.round(performance.now() - t0));
    if (code !== 0) {
      return bad(code);
    }
    if (i === 4) {
      console.error(JSON.stringify({
        mode: mode,
        total_ms: Math.round(performance.now() - t0),
        marks: marks,
        alpn: Atomics.load(b.ia, P0_ALPN),
        authorized: Atomics.load(b.ia, P0_AUTH),
        bytes: got.length,
        head: got.slice(0, 12),
      }));
      return marks[4];
    }
    const done = Atomics.load(b.ia, P0_DONE_SEQ);
    if (i === 0) {
      Atomics.store(b.ia, P0_PORT, port);
      // Loopback self-signed: ALPN http/1.1 only, no chain check
      // (the flag bit 2 would turn verification on).
      Atomics.store(b.ia, P0_FLAGS, 3);
      const s8 = b.enc.encode(sni);
      new Uint8Array(b.sab, P0_SNI_AT, s8.length).set(s8);
      Atomics.store(b.ia, P0_SNI_LEN, s8.length);
      const i8 = b.enc.encode(ip);
      new Uint8Array(b.sab, P0_IP_AT, i8.length).set(i8);
      Atomics.store(b.ia, P0_IP_LEN, i8.length);
      Atomics.store(b.ia, P0_STATE, 0);
      p0_request(b, P0_CONNECT, undefined, "");
    } else if (i === 1) {
      Atomics.store(b.ia, P0_STATE, 0);
      p0_request(b, P0_SEND, undefined, req);
    } else if (i === 2) {
      Atomics.store(b.ia, P0_STATE, 0);
      p0_request(b, P0_RECV, 4096, "");
    } else {
      got = b.dec.decode(new Uint8Array(b.sab, P0_PAY_AT,
        Atomics.load(b.ia, P0_LEN)));
      Atomics.store(b.ia, P0_STATE, 0);
      p0_request(b, P0_CLOSE, undefined, "");
    }
    return p0_wait(b, mode, done, k, () => step(i + 1));
  };
  return step(0);
}
