// Native WebSocket client for ping/pong interop with Bend.
// No dependencies: manual RFC 6455 over node:net (masked sends, like a
// browser would; the `ws` auto-pong/auto-close behavior is scripted by
// hand). Same 6-step script as client.js: connect -> ping "s1"
// (auto-pong, no manual reply) -> ping "c1" -> pong "c1" ->
// text "hello" -> echo -> ping "s2" (auto-pong) -> server close
// (auto-reply). Prints one line per check and DONE n/6.
// Usage: node client_native.js [port] (default port 19880)

import * as net from "node:net";

const PORT = Number(process.argv[2] ?? 19880);
const STEP_TIMEOUT_MS = 5000;
const KEY = "dGhlIHNhbXBsZSBub25jZQ==";
const MASK = Buffer.from([1, 2, 3, 4]);

let score = 0;

/**
 * Fails the session unless `cond` holds.
 *
 * @param cond {boolean} - The check result.
 * @param name - Check label for the log.
 * @param detail - Extra context on failure.
 */
function check(cond, name, detail) {
  if (!cond) {
    console.log(`FAIL ${name}: ${detail}`);
    process.exitCode = 1;
    throw new Error(`FAIL ${name}`);
  }
  score += 1;
  console.log(`OK ${name}`);
}

/**
 * Total WS frame length from the length prefix alone.
 *
 * @param buf {Buffer} - Bytes held so far.
 */
function frame_need(buf) {
  if (buf.length < 2) return 0;
  const len7 = buf[1] & 127;
  const ext = len7 === 126 ? 2 : len7 === 127 ? 8 : 0;
  if (buf.length < 2 + ext) return 0;
  let pay = len7;
  if (len7 === 126) pay = buf.readUInt16BE(2);
  if (len7 === 127) pay = Number(buf.readBigUInt64BE(2));
  return 2 + ext + (buf[1] & 128 ? 4 : 0) + pay;
}

/**
 * Parses one complete frame. Server frames arrive unmasked.
 *
 * @param buf {Buffer} - Exactly one frame's bytes.
 */
function frame_parse(buf) {
  const fin = (buf[0] & 128) !== 0;
  const op = buf[0] & 15;
  const masked = (buf[1] & 128) !== 0;
  const len7 = buf[1] & 127;
  const ext = len7 === 126 ? 2 : len7 === 127 ? 8 : 0;
  let pay;
  if (len7 === 126) pay = buf.readUInt16BE(2);
  else if (len7 === 127) pay = Number(buf.readBigUInt64BE(2));
  else pay = len7;
  let payload = buf.subarray(2 + ext, 2 + ext + pay);
  if (masked) {
    const mask = buf.subarray(2 + ext, 2 + ext + 4);
    payload = Buffer.from(payload);
    for (let i = 0; i < payload.length; i += 1) {
      payload[i] ^= mask[i % 4];
    }
  }
  return { fin, op, payload };
}

/**
 * Encodes one masked client frame.
 *
 * @param op {number} - Opcode.
 * @param payload {Buffer} - Raw payload bytes.
 */
function frame_show(op, payload) {
  const len = payload.length;
  let head;
  if (len <= 125) head = Buffer.from([128 | op, 128 | len]);
  else if (len <= 65535) {
    head = Buffer.alloc(4);
    head[0] = 128 | op;
    head[1] = 254;
    head.writeUInt16BE(len, 2);
  } else {
    head = Buffer.alloc(10);
    head[0] = 128 | op;
    head[1] = 255;
    head.writeBigUInt64BE(BigInt(len), 2);
  }
  const enc = Buffer.alloc(len);
  for (let i = 0; i < len; i += 1) {
    enc[i] = payload[i] ^ MASK[i % 4];
  }
  return Buffer.concat([head, MASK, enc]);
}

/** Incremental frame reader over a socket. */
class Framer {
  /** @param sock {net.Socket} */
  constructor(sock) {
    this.sock = sock;
    this.buf = Buffer.alloc(0);
    this.waiters = [];
    sock.on("data", (chunk) => this.push(chunk));
    sock.on("close", () => this.fail(new Error("eof")));
    sock.on("error", () => {});
  }
  /** @param chunk {Buffer} */
  push(chunk) {
    this.buf = Buffer.concat([this.buf, chunk]);
    this.pump();
  }
  /** @param err {Error} */
  fail(err) {
    for (const w of this.waiters.splice(0)) w.reject(err);
  }
  pump() {
    while (this.waiters.length > 0) {
      const total = frame_need(this.buf);
      if (total === 0 || this.buf.length < total) return;
      const frame = this.buf.subarray(0, total);
      this.buf = this.buf.subarray(total);
      const w = this.waiters.shift();
      try {
        w.resolve(frame_parse(frame));
      } catch (err) {
        w.reject(err);
      }
    }
  }
  next() {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const at = this.waiters.indexOf(w);
        if (at >= 0) this.waiters.splice(at, 1);
        reject(new Error("timeout waiting for frame"));
      }, STEP_TIMEOUT_MS);
      const w = {
        resolve: (f) => {
          clearTimeout(timer);
          resolve(f);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      };
      this.waiters.push(w);
      this.pump();
    });
  }
}

/** Runs the 6-step script against the server at PORT. */
async function main() {
  const sock = net.connect(PORT, "127.0.0.1");
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timeout waiting for open")), STEP_TIMEOUT_MS);
    sock.once("connect", () => {
      clearTimeout(timer);
      resolve();
    });
    sock.once("error", reject);
  });
  sock.write(
    `GET /chat HTTP/1.1\r\nHost: 127.0.0.1:${PORT}\r\n`
    + "Upgrade: websocket\r\nConnection: Upgrade\r\n"
    + `Sec-WebSocket-Key: ${KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n`,
  );
  const hs = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timeout waiting for 101")), STEP_TIMEOUT_MS);
    let raw = Buffer.alloc(0);
    const on_data = (chunk) => {
      raw = Buffer.concat([raw, chunk]);
      const at = raw.indexOf("\r\n\r\n");
      if (at >= 0) {
        clearTimeout(timer);
        sock.removeListener("data", on_data);
        resolve({ head: raw.subarray(0, at).toString("latin1"), rest: raw.subarray(at + 4) });
      }
    };
    sock.on("data", on_data);
    sock.on("error", () => {});
  });
  check(hs.head.includes("101"), "HS", "connected");
  const framer = new Framer(sock);
  framer.push(hs.rest); // frames glued to the 101 head are kept
  // (The Bend servers answer 101 before reading, but their ping s1 may
  // still arrive in the same TCP packet as the head.)
  /** @param op {number} @param payload {Buffer} */
  const send = (op, payload) => sock.write(frame_show(op, payload));
  try {
    let f = await framer.next();
    check(f.op === 9 && f.payload.equals(Buffer.from("s1")), "PING_S1", `op=${f.op}`);
    send(10, f.payload); // client auto-pongs, like `ws` does

    send(9, Buffer.from("c1"));
    f = await framer.next();
    check(f.op === 10 && f.payload.equals(Buffer.from("c1")), "PONG_C1", `op=${f.op}`);

    send(1, Buffer.from("hello"));
    f = await framer.next();
    check(f.op === 1 && f.payload.toString() === "hello", "ECHO", `op=${f.op}`);

    f = await framer.next();
    check(f.op === 9 && f.payload.equals(Buffer.from("s2")), "PING_S2", `op=${f.op}`);
    send(10, f.payload); // auto-pong; the server scores it

    f = await framer.next();
    check(f.op === 8, "CLOSE", `op=${f.op}`);
    send(8, f.payload); // auto-reply to the server close

    console.log(`DONE ${score}/6`);
  } catch (err) {
    if (process.exitCode !== 1) {
      console.log(`FAIL session: ${err.message}`);
      process.exitCode = 1;
    }
  } finally {
    sock.destroy();
  }
}

await main();
