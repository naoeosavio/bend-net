// Load generator for the H2 stress matrix (task-063). Manual only.
// Start examples/httpx/stress_h2.bend first, then:
//   node examples/httpx/stress_h2.js conns   <port> <n> <reqs>
//   node examples/httpx/stress_h2.js waves   <port> <waves> <streams>
//   node examples/httpx/stress_h2.js bigdown <port> <mb> <times>
//   node examples/httpx/stress_h2.js flood   <port> <n>
//   node examples/httpx/stress_h2.js pings   <port> <n>
//   node examples/httpx/stress_h2.js abort   <port> <n>
//   node examples/httpx/stress_h2.js hughead <port>            (>64 KiB block -> GOAWAY 11)
import tls from "node:tls";
import { connect } from "node:http2";
import { readFileSync } from "node:fs";

const MODE = process.argv[2];
const PORT = Number(process.argv[3]);
const A = Number(process.argv[4] ?? 1);
const B = Number(process.argv[5] ?? 1);
const CERT = readFileSync("tests/io/tls_test_cert.pem");
const KEY = readFileSync("tests/io/tls_test_key.pem");
const PREFACE = Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
const T = { 0: "DATA", 1: "HEADERS", 3: "RST", 4: "SETTINGS", 6: "PING", 7: "GOAWAY", 8: "WU", 9: "CONT" };
const BODY = Buffer.alloc(1024, 97);

const t0 = Date.now();
const ms = () => Date.now() - t0;
const say = (s) => console.log(s);
const done = (ok, s) => { say(`${ok ? "DONE" : "FAIL"} ${s} ms=${ms()}`); process.exit(ok ? 0 : 1); };

function mbSafe(v) { return v; }

function session() {
  return connect(`https://127.0.0.1:${PORT}`, {
    rejectUnauthorized: false,
    tls: { rejectUnauthorized: false },
    maxSessionMemory: 2048,
    settings: { maxConcurrentStreams: 1000 },
  });
}

function frame(typ, flags, sid, pay) {
  const h = Buffer.alloc(9);
  h.writeUIntBE(pay.length, 0, 3);
  h[3] = typ;
  h[4] = flags;
  h.writeUInt32BE(sid, 5);
  return Buffer.concat([h, pay]);
}

function lit(n, v) {
  const a = Buffer.from(n);
  const b = Buffer.from(v);
  return Buffer.concat([Buffer.from([0, a.length]), a, Buffer.from([b.length]), b]);
}

function parse(onFrame, pre) {
  let buf = Buffer.alloc(0);
  let first = pre;
  return (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    if (first) {
      if (buf.length < 24) return;
      buf = buf.subarray(24);
      first = false;
    }
    for (;;) {
      if (buf.length < 9) return;
      const len = buf.readUIntBE(0, 3);
      const typ = buf[3];
      const flags = buf[4];
      const sid = buf.readUInt32BE(5) & 0x7fffffff;
      if (buf.length < 9 + len) return;
      const pay = buf.subarray(9, 9 + len);
      buf = buf.subarray(9 + len);
      onFrame(typ, flags, sid, pay);
    }
  };
}

async function echoOnce(s, path = "/echo") {
  return new Promise((resolve) => {
    const req = s.request({ ":method": "POST", ":path": path, "content-length": String(BODY.length) });
    let got = 0;
    let status = 0;
    req.on("response", (h) => { status = Number(h[":status"]); });
    req.on("data", (c) => { got += c.length; });
    req.on("error", () => resolve(false));
    req.on("close", () => resolve(status === 200 && got === BODY.length));
    req.end(BODY);
  });
}

if (MODE === "conns") {
  const N = A;
  const R = B;
  let ok = 0;
  let bad = 0;
  const one = async () => {
    const s = session();
    s.on("error", () => {});
    for (let i = 0; i < R; i += 1) {
      if (await echoOnce(s)) ok += 1; else bad += 1;
    }
    s.close();
  };
  await Promise.all(Array.from({ length: N }, one));
  done(bad === 0, `conns n=${N} reqs=${R} ok=${ok} bad=${bad} rps=${Math.round((ok + bad) / ((Date.now() - t0) / 1000))}`);
}

if (MODE === "waves") {
  const W = A;
  const S = B;
  const s = session();
  s.on("error", () => {});
  let ok = 0;
  let bad = 0;
  for (let w = 0; w < W; w += 1) {
    const rs = await Promise.all(Array.from({ length: S }, () => echoOnce(s)));
    for (const r of rs) { if (r) ok += 1; else bad += 1; }
  }
  s.close();
  done(bad === 0, `waves w=${W} streams=${S} ok=${ok} bad=${bad} sps=${Math.round((ok + bad) / ((Date.now() - t0) / 1000))}`);
}

if (MODE === "upwaves") {
  const W = A;
  const S = B;
  const KB = Number(process.argv[6] ?? 64);
  const payload = Buffer.alloc(KB * 1024, 97);
  const s = session();
  s.on("error", () => {});
  let ok = 0;
  let bad = 0;
  const one = () => new Promise((resolve) => {
    const req = s.request({ ":method": "POST", ":path": "/echo", "content-length": String(payload.length) });
    let status = 0;
    req.on("response", (h) => { status = Number(h[":status"]); });
    req.on("data", () => {});
    req.on("error", () => { bad += 1; resolve(); });
    req.on("close", () => { if (status === 200) ok += 1; else bad += 1; resolve(); });
    req.end(payload);
  });
  for (let w = 0; w < W; w += 1) {
    await Promise.all(Array.from({ length: S }, one));
  }
  s.close();
  done(bad === 0, `upwaves w=${W} streams=${S} kb=${KB} ok=${ok} bad=${bad} mbps=${((ok * KB) / 1024 / ((Date.now() - t0) / 1000)).toFixed(1)}`);
}

// Credit peer: N concurrent POSTs on one connection, raw H2, and the peer
// counts the windows it grants. The cell fails when the server sends a
// DATA byte past the credit it gave (RFC 9113 section 6.9.1). The peer
// grants at half of the initial window, like node:http2, and sends its own
// bodies inside the windows the server announces.
if (MODE === "credit") {
  const N = A;
  const KB = B;
  const BODY2 = Buffer.alloc(KB * 1024, 97);
  const sids = Array.from({ length: N }, (_, i) => 1 + 2 * i);
  const sock = tls.connect({
    host: "127.0.0.1", port: PORT, ALPNProtocols: ["h2"], rejectUnauthorized: false,
  });
  const streams = new Map();
  for (const sid of sids) streams.set(sid, { off: 0, win: 65535, grant: 65535, got: 0, pend: 0, end: false });
  let connSend = 65535;
  let connGrant = 65535;
  let connGot = 0;
  let connPend = 0;
  let ended = 0;
  let bad = "";
  const u32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32BE(v); return b; };
  const fail = (s) => { if (bad === "") { bad = s; } done(false, `credit ${s} bytes=${connGot} ended=${ended}`); };
  const pump = () => {
    for (const sid of sids) {
      const s = streams.get(sid);
      while (s.off < BODY2.length) {
        const room = Math.min(connSend, s.win, 16384, BODY2.length - s.off);
        if (room <= 0) break;
        const fin = s.off + room === BODY2.length;
        sock.write(frame(0, fin ? 1 : 0, sid, BODY2.subarray(s.off, s.off + room)));
        s.off += room; s.win -= room; connSend -= room;
      }
    }
  };
  const onFrame = (typ, flags, sid, pay) => {
    if (process.env.VERBOSE) say(`  < ${T[typ] ?? typ} flags=${flags} sid=${sid} len=${pay.length}`);
    if (typ === 4 && (flags & 1) === 0) { sock.write(frame(4, 1, 0, Buffer.alloc(0))); return; }
    if (typ === 6 && (flags & 1) === 0) { sock.write(frame(6, 1, 0, pay)); return; }
    if (typ === 7) { fail(`session goaway code=${pay.readUInt32BE(4)}`); return; }
    if (typ === 3) { fail(`stream ${sid} reset code=${pay.readUInt32BE(0)}`); return; }
    if (typ === 8) {
      const inc = pay.readUInt32BE(0);
      if (sid === 0) { connSend += inc; } else if (streams.has(sid)) { streams.get(sid).win += inc; }
      pump();
      return;
    }
    if (typ !== 0) return;
    const s = streams.get(sid);
    connGot += pay.length;
    connPend += pay.length;
    if (s) { s.got += pay.length; s.pend += pay.length; }
    if (connGot > connGrant) fail(`connection DATA ${connGot} past granted ${connGrant}`);
    if (s && s.got > s.grant) fail(`stream ${sid} DATA ${s.got} past granted ${s.grant}`);
    if (connPend >= 32768) { sock.write(frame(8, 0, 0, u32(connPend))); connGrant += connPend; connPend = 0; }
    if (s && s.pend >= 32768) { sock.write(frame(8, 0, sid, u32(s.pend))); s.grant += s.pend; s.pend = 0; }
    if (flags & 1) {
      s.end = true;
      ended += 1;
      if (s.got !== BODY2.length) fail(`stream ${sid} ended at ${s.got} bytes, want ${BODY2.length}`);
      if (ended === N) done(bad === "" && connGot === N * BODY2.length, `credit streams=${N} kb=${KB} bytes=${connGot} ended=${ended} ${bad}`);
    }
  };
  sock.on("secureConnect", () => {
    sock.write(PREFACE);
    sock.write(frame(4, 0, 0, Buffer.alloc(0)));
    const blk = Buffer.concat([
      lit(":method", "POST"), lit(":path", "/echo"), lit(":scheme", "https"),
      lit(":authority", `127.0.0.1:${PORT}`), lit("content-length", String(BODY2.length)),
    ]);
    for (const sid of sids) sock.write(frame(1, 4, sid, blk));
    pump();
  });
  sock.on("data", parse(onFrame, false));
  sock.on("error", (e) => done(false, `credit socket ${e.message}`));
  setTimeout(() => done(false, `credit timeout bytes=${connGot} ended=${ended} ${bad}`), 20000).unref();
}

if (MODE === "bigdown") {
  const MB = A;
  const TIMES = B;
  const s = session();
  s.on("error", (e) => done(false, `session ${e.message}`));
  let total = 0;
  const one = () => new Promise((resolve) => {
    const req = s.request({ ":method": "GET", ":path": "/big" });
    let got = 0;
    req.on("data", (c) => { got += c.length; });
    req.on("error", (e) => { say(`FAIL req ${e.message}`); resolve(false); });
    req.on("end", () => { total += got; resolve(got === MB * 1024 * 1024); });
    req.end();
  });
  let ok = true;
  for (let i = 0; i < TIMES; i += 1) { ok = (await one()) && ok; }
  s.close();
  const secs = (Date.now() - t0) / 1000;
  done(ok, `bigdown mb=${MB} times=${TIMES} bytes=${total} mbps=${(total / 1048576 / secs).toFixed(1)}`);
}

if (MODE === "bigconc") {
  const N = A;
  const MB = B;
  const want = N * MB * 1024 * 1024;
  let total = 0;
  const one = () => new Promise((resolve) => {
    const s = session();
    s.on("error", () => resolve(false));
    const req = s.request({ ":method": "GET", ":path": "/big" });
    let got = 0;
    req.on("data", (c) => { got += c.length; });
    req.on("end", () => { total += got; s.close(); resolve(got === MB * 1024 * 1024); });
    req.on("error", () => resolve(false));
    req.end();
  });
  const rs = await Promise.all(Array.from({ length: N }, one));
  const ok = rs.filter(Boolean).length;
  const secs = (Date.now() - t0) / 1000;
  done(ok === N && total === want, `bigconc conns=${N} mb=${MB} ok=${ok} bytes=${total} mbps=${(total / 1048576 / secs).toFixed(1)}`);
}

if (MODE === "bigwaves") {
  const S = A;
  const MB = B;
  const want = S * MB * 1024 * 1024;
  const s = session();
  s.on("error", () => {});
  let total = 0;
  const one = () => new Promise((resolve) => {
    const req = s.request({ ":method": "GET", ":path": "/big" });
    let got = 0;
    req.on("data", (c) => { got += c.length; });
    req.on("end", () => { total += got; resolve(got === MB * 1024 * 1024); });
    req.on("error", () => resolve(false));
    req.end();
  });
  const rs = await Promise.all(Array.from({ length: S }, one));
  const ok = rs.filter(Boolean).length;
  s.close();
  const secs = (Date.now() - t0) / 1000;
  done(ok === S && total === want, `bigwaves streams=${S} mb=${mbSafe(MB)} ok=${ok} bytes=${total} mbps=${(total / 1048576 / secs).toFixed(1)}`);
}

if (MODE === "flood") {
  const N = A;
  const sock = tls.connect({ host: "127.0.0.1", port: PORT, ALPNProtocols: ["h2"], rejectUnauthorized: false });
  let refused = 0;
  let other = 0;
  sock.on("secureConnect", () => {
    sock.write(PREFACE);
    sock.write(frame(4, 0, 0, Buffer.alloc(0)));
    const blk = Buffer.concat([
      lit(":method", "GET"), lit(":path", "/echo"),
      lit(":scheme", "https"), lit(":authority", `127.0.0.1:${PORT}`),
    ]);
    for (let i = 0; i < N; i += 1) {
      sock.write(frame(1, 4, 1 + 2 * i, blk));
    }
  });
  sock.on("data", parse((typ, flags, sid, pay) => {
    if (typ === 4 && (flags & 1) === 0) { sock.write(frame(4, 1, 0, Buffer.alloc(0))); return; }
    if (typ === 3) { if (pay.readUInt32BE(0) === 7) refused += 1; else other += 1; }
  }, false));
  sock.on("error", (e) => done(false, `socket ${e.message}`));
  setTimeout(() => done(refused >= N - 100, `flood n=${N} refused=${refused} other=${other}`), 6000).unref();
}

if (MODE === "pings") {
  const N = A;
  const sock = tls.connect({ host: "127.0.0.1", port: PORT, ALPNProtocols: ["h2"], rejectUnauthorized: false });
  let acks = 0;
  let extras = 0;
  const sent = new Set();
  sock.on("secureConnect", () => {
    sock.write(PREFACE);
    sock.write(frame(4, 0, 0, Buffer.alloc(0)));
    for (let i = 0; i < N; i += 1) {
      const p = Buffer.alloc(8);
      p.writeUInt32BE(i, 4);
      sent.add(p.toString("hex"));
      sock.write(frame(6, 0, 0, p));
    }
  });
  sock.on("data", parse((typ, flags, sid, pay) => {
    if (typ === 4 && (flags & 1) === 0) { sock.write(frame(4, 1, 0, Buffer.alloc(0))); return; }
    if (typ === 6) {
      if ((flags & 1) === 1 && sent.has(pay.toString("hex"))) acks += 1;
      else extras += 1;
    }
  }, false));
  sock.on("error", (e) => done(false, `socket ${e.message}`));
  setTimeout(() => done(acks === N && extras === 0, `pings n=${N} acks=${acks} extras=${extras}`), 15000).unref();
}

if (MODE === "abort") {
  const N = A;
  let aborted = 0;
  const one = () => new Promise((resolve) => {
    const sock = tls.connect({ host: "127.0.0.1", port: PORT, ALPNProtocols: ["h2"], rejectUnauthorized: false });
    sock.on("secureConnect", () => {
      sock.write(PREFACE);
      sock.write(frame(4, 0, 0, Buffer.alloc(0)));
      const blk = Buffer.concat([
        lit(":method", "GET"), lit(":path", "/big"),
        lit(":scheme", "https"), lit(":authority", `127.0.0.1:${PORT}`),
      ]);
      sock.write(frame(1, 5, 1, blk));
    });
    sock.on("data", () => {
      aborted += 1;
      sock.destroy();
      resolve(true);
    });
    sock.on("error", () => resolve(true));
    setTimeout(() => { sock.destroy(); resolve(true); }, 5000).unref();
  });
  await Promise.all(Array.from({ length: N }, one));
  // The server must still answer a fresh client after the rude burst:
  // status 200 is enough, the body size belongs to the server mode.
  const s = session();
  s.on("error", () => {});
  const alive = await new Promise((resolve) => {
    const req = s.request({ ":method": "GET", ":path": "/big" });
    let status = 0;
    req.on("response", (h) => { status = Number(h[":status"]); });
    req.on("data", () => {});
    req.on("error", () => resolve(false));
    req.on("close", () => resolve(status === 200));
    req.end();
  });
  s.close();
  done(alive, `abort n=${N} aborted=${aborted} server_alive=${alive}`);
}

if (MODE === "hughead") {
  const sock = tls.connect({ host: "127.0.0.1", port: PORT, ALPNProtocols: ["h2"], rejectUnauthorized: false });
  sock.on("secureConnect", () => {
    sock.write(PREFACE);
    sock.write(frame(4, 0, 0, Buffer.alloc(0)));
    const blk = Buffer.concat([
      lit(":method", "GET"), lit(":path", "/echo"),
      lit(":scheme", "https"), lit(":authority", `127.0.0.1:${PORT}`),
      lit("x-huge", "h".repeat(70000)),
    ]);
    const step = 16384;
    sock.write(frame(1, 0, 1, blk.subarray(0, step)));
    for (let i = step; i < blk.length; i += step) {
      const end = Math.min(i + step, blk.length);
      sock.write(frame(9, end === blk.length ? 4 : 0, 1, blk.subarray(i, end)));
    }
  });
  sock.on("data", parse((typ, flags, sid, pay) => {
    if (typ === 4 && (flags & 1) === 0) { sock.write(frame(4, 1, 0, Buffer.alloc(0))); return; }
    if (typ === 7) done(pay.readUInt32BE(4) === 11, `hughead goaway code=${pay.readUInt32BE(4)} want=11`);
  }, false));
  sock.on("error", (e) => done(false, `socket ${e.message}`));
  setTimeout(() => done(false, "hughead timeout"), 10000).unref();
}
