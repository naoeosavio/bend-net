// Native WebSocket server for ping/pong interop with Bend.
// No dependencies: manual RFC 6455 over node:net (Upgrade + SHA-1
// Accept + incremental frame parser). Same 6-step script as server.js:
// accept -> ping "s1" -> pong "s1" -> ping "c1" -> auto-pong ->
// text "hello" -> echo + ping "s2" -> pong "s2" -> close.
// Prints one line per check and DONE n/6.
// Usage: node server_native.js [port] (default port 19880)

import * as net from "node:net";
import * as crypto from "node:crypto";

const PORT = Number(process.argv[2] ?? 19880);
const STEP_TIMEOUT_MS = 5000;
const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

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
 * Total WS frame length from the length prefix alone (2 + ext + mask +
 * payload). Returns 0 while the header itself is short.
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
 * Parses one complete frame. Client frames must be masked (RFC 6455).
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
  if (!masked) throw new Error("unmasked client frame");
  const mask = buf.subarray(2 + ext, 2 + ext + 4);
  const enc = buf.subarray(2 + ext + 4, 2 + ext + 4 + pay);
  const payload = Buffer.alloc(enc.length);
  for (let i = 0; i < enc.length; i += 1) {
    payload[i] = enc[i] ^ mask[i % 4];
  }
  return { fin, op, payload };
}

/**
 * Encodes one unmasked server frame.
 *
 * @param op {number} - Opcode (1 text, 2 binary, 8 close, 9 ping, 10 pong).
 * @param payload {Buffer} - Raw payload bytes.
 */
function frame_show(op, payload) {
  const len = payload.length;
  let head;
  if (len <= 125) head = Buffer.from([128 | op, len]);
  else if (len <= 65535) {
    head = Buffer.alloc(4);
    head[0] = 128 | op;
    head[1] = 126;
    head.writeUInt16BE(len, 2);
  } else {
    head = Buffer.alloc(10);
    head[0] = 128 | op;
    head[1] = 127;
    head.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([head, payload]);
}

/** Incremental frame reader over a socket. */
class Framer {
  /** @param sock {net.Socket} */
  constructor(sock) {
    this.sock = sock;
    this.buf = Buffer.alloc(0);
    this.waiters = [];
    this.ended = false;
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
    this.ended = true;
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

/**
 * Validates the opening handshake and answers 101.
 *
 * @param sock {net.Socket} - The fresh connection.
 */
function handshake(sock) {
  return new Promise((resolve, reject) => {
    let raw = Buffer.alloc(0);
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error("timeout waiting for handshake"));
    }, STEP_TIMEOUT_MS);
    const cleanup = () => {
      clearTimeout(timer);
      sock.removeListener("data", on_data);
    };
    const on_data = (chunk) => {
      raw = Buffer.concat([raw, chunk]);
      if (raw.length > 16384) {
        cleanup();
        reject(new Error("head too large"));
        return;
      }
      const at = raw.indexOf("\r\n\r\n");
      if (at < 0) return;
      const head = raw.subarray(0, at).toString("latin1");
      const rest = raw.subarray(at + 4);
      const lines = head.split("\r\n");
      const top = lines[0].split(" ");
      const hs = new Map();
      for (const ln of lines.slice(1)) {
        const i = ln.indexOf(":");
        if (i > 0) hs.set(ln.slice(0, i).trim().toLowerCase(), ln.slice(i + 1).trim());
      }
      const key = hs.get("sec-websocket-key") ?? "";
      const ok = top[0] === "GET"
        && (hs.get("upgrade") ?? "").toLowerCase() === "websocket"
        && (hs.get("sec-websocket-version") ?? "") === "13"
        && key !== ""
        && (hs.get("connection") ?? "").toLowerCase().includes("upgrade");
      cleanup();
      if (!ok) {
        reject(new Error("bad handshake"));
        return;
      }
      const accept = crypto.createHash("sha1").update(key + GUID).digest("base64");
      sock.write(
        "HTTP/1.1 101 Switching Protocols\r\n"
        + "Upgrade: websocket\r\n"
        + "Connection: Upgrade\r\n"
        + `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
      );
      resolve(rest);
    };
    sock.on("data", on_data);
    sock.on("error", () => {});
  });
}

/** @param sock {net.Socket} */
async function run_session(sock) {
  const rest = await handshake(sock);
  check(true, "HS", "accepted");
  const framer = new Framer(sock);
  framer.push(rest); // frames glued to the handshake head are kept
  /** @param op {number} @param payload {Buffer} */
  const send = (op, payload) => sock.write(frame_show(op, payload));

  send(9, Buffer.from("s1"));
  let f = await framer.next();
  check(f.op === 10 && f.payload.equals(Buffer.from("s1")), "PONG_S1", `op=${f.op}`);

  f = await framer.next();
  check(f.op === 9 && f.payload.equals(Buffer.from("c1")), "PING_C1", `op=${f.op}`);
  send(10, f.payload); // server auto-pongs, like `ws` does

  f = await framer.next();
  check(f.op === 1 && f.payload.toString() === "hello", "TEXT", `op=${f.op}`);
  send(1, Buffer.from("hello"));
  console.log("SENT echo");
  send(9, Buffer.from("s2"));

  f = await framer.next();
  check(f.op === 10 && f.payload.equals(Buffer.from("s2")), "PONG_S2", `op=${f.op}`);

  send(8, Buffer.alloc(0));
  f = await framer.next();
  check(f.op === 8, "CLOSE", `op=${f.op}`);

  console.log(`DONE ${score}/6`);
}

const server = net.createServer((sock) => {
  if (server.session_taken) {
    sock.destroy();
    return;
  }
  server.session_taken = true;
  run_session(sock).then(
    () => server.close(),
    (err) => {
      if (process.exitCode !== 1) {
        console.log(`FAIL session: ${err.message}`);
        process.exitCode = 1;
      }
      sock.destroy();
      server.close();
    },
  );
});
server.session_taken = false;
server.listen(PORT, "127.0.0.1", () => {
  console.log(`LISTEN ${PORT}`);
});
