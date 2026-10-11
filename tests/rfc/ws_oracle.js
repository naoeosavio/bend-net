// WS oracle: native WebSocket echo for RFC 6455 conformance. Builtins
// only (node:net, node:crypto), so the same file runs under node and
// bun — no `ws` dependency. Two modes:
//   node ws_oracle.js server [port] [n]  — echo server, DONE n/n
//     (n = text/binary echoes before closing)
//   node ws_oracle.js client <port>       — 6-step script vs any server
//     (Bend or this oracle): 101, ping/pong both ways, hello echo,
//     close. DONE 6/6
import * as net from "node:net";
import * as crypto from "node:crypto";

const MODE = process.argv[2] ?? "server";
const PORT = Number(process.argv[3] ?? 19884);
const DONE_AFTER = Number(process.argv[4] ?? 2);
const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const STEP_TIMEOUT_MS = 5000;
const KEY = "dGhlIHNhbXBsZSBub25jZQ==";
const MASK = Buffer.from([7, 250, 33, 61]);

let score = 0;

/**
 * Fails the run unless `cond` holds.
 *
 * @param cond {boolean} - The check result.
 * @param name {string} - Check label for the log.
 */
function check(cond, name) {
  if (!cond) {
    console.log(`FAIL ${name}`);
    process.exitCode = 1;
    throw new Error(`FAIL ${name}`);
  }
  score += 1;
  console.log(`OK ${name}`);
}

/**
 * Frame total from the length prefix (0 while the header is short).
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
 * Parses one frame, unmasking when masked.
 *
 * @param buf {Buffer} - Exactly one frame's bytes.
 * @param masked {boolean} - True for client frames.
 */
function frame_parse(buf, masked) {
  const fin = (buf[0] & 128) !== 0;
  const op = buf[0] & 15;
  const len7 = buf[1] & 127;
  const ext = len7 === 126 ? 2 : len7 === 127 ? 8 : 0;
  let pay = len7;
  if (len7 === 126) pay = buf.readUInt16BE(2);
  if (len7 === 127) pay = Number(buf.readBigUInt64BE(2));
  let start = 2 + ext;
  let mask = null;
  if (buf[1] & 128) {
    mask = buf.subarray(start, start + 4);
    start += 4;
  }
  let payload = buf.subarray(start, start + pay);
  if (mask) {
    payload = Buffer.from(payload);
    for (let i = 0; i < payload.length; i += 1) {
      payload[i] ^= mask[i % 4];
    }
  }
  if (masked && !mask) throw new Error("unmasked client frame");
  return { fin, op, payload };
}

/**
 * Encodes one frame, masked for the client side when asked.
 *
 * @param op {number} - Opcode.
 * @param payload {Buffer} - Raw payload.
 * @param mask {boolean} - Mask the frame.
 */
function frame_show(op, payload, mask) {
  const len = payload.length;
  let head;
  const b1 = mask ? 128 | len : len;
  if (len <= 125) head = Buffer.from([128 | op, b1]);
  else if (len <= 65535) {
    head = Buffer.alloc(4);
    head[0] = 128 | op;
    head[1] = mask ? 254 : 126;
    head.writeUInt16BE(len, 2);
  } else {
    head = Buffer.alloc(10);
    head[0] = 128 | op;
    head[1] = mask ? 255 : 127;
    head.writeBigUInt64BE(BigInt(len), 2);
  }
  if (!mask) return Buffer.concat([head, payload]);
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
    sock.on("data", (c) => this.push(c));
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
      const raw = this.buf.subarray(0, total);
      this.buf = this.buf.subarray(total);
      const w = this.waiters.shift();
      try {
        w.resolve(raw);
      } catch (err) {
        w.reject(err);
      }
    }
  }
  next() {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error("timeout waiting for frame"));
      }, STEP_TIMEOUT_MS);
      this.waiters.push({
        resolve: (f) => {
          clearTimeout(timer);
          resolve(f);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      });
      this.pump();
    });
  }
}

/**
 * Reads the HTTP head up to the blank line, keeping the rest.
 *
 * @param sock {net.Socket} - The fresh connection.
 */
function read_head(sock) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("head timeout")), STEP_TIMEOUT_MS);
    let raw = Buffer.alloc(0);
    const on_data = (chunk) => {
      raw = Buffer.concat([raw, chunk]);
      if (raw.length > 16384) {
        clearTimeout(timer);
        reject(new Error("head too large"));
        return;
      }
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
}

/** Runs the echo server: handshake, echo data, auto-pong, close. */
function serve() {
  const server = net.createServer((sock) => {
    read_head(sock).then(({ head, rest }) => {
      const lines = head.split("\r\n");
      const hs = new Map();
      for (const ln of lines.slice(1)) {
        const i = ln.indexOf(":");
        if (i > 0) hs.set(ln.slice(0, i).trim().toLowerCase(), ln.slice(i + 1).trim());
      }
      const key = hs.get("sec-websocket-key") ?? "";
      const ok = lines[0].startsWith("GET")
        && (hs.get("upgrade") ?? "").toLowerCase() === "websocket"
        && (hs.get("sec-websocket-version") ?? "") === "13"
        && key !== "";
      if (!ok) {
        sock.destroy();
        return;
      }
      const accept = crypto.createHash("sha1").update(key + GUID).digest("base64");
      // A browser (and node's WebSocket) fails the handshake when it asked
      // for a subprotocol and the 101 does not echo one, so the first
      // requested protocol is picked -- the browser leg asks for "chat".
      const wanted = (hs.get("sec-websocket-protocol") ?? "").split(",")[0].trim();
      const proto = wanted === "" ? "" : `Sec-WebSocket-Protocol: ${wanted}\r\n`;
      sock.write(
        "HTTP/1.1 101 Switching Protocols\r\n"
        + "Upgrade: websocket\r\n"
        + "Connection: Upgrade\r\n"
        + `Sec-WebSocket-Accept: ${accept}\r\n`
        + proto
        + "\r\n",
      );
      sock.write(frame_show(9, Buffer.from("s1"), false));
      check(true, "HS");
      const framer = new Framer(sock);
      framer.push(rest);
      let echoes = 0;
      const loop = async () => {
        for (;;) {
          const raw = await framer.next();
          const f = frame_parse(raw, true);
          if (f.op === 9) {
            sock.write(frame_show(10, f.payload, false));
          } else if (f.op === 1 || f.op === 2) {
            sock.write(frame_show(f.op, f.payload, false));
            echoes += 1;
            console.log(`OK ECHO op=${f.op} len=${f.payload.length}`);
            if (echoes >= DONE_AFTER) {
              console.log(`DONE ${score + echoes}/${score + echoes}`);
              sock.write(frame_show(8, Buffer.alloc(0), false));
              sock.end();
              server.close();
              return;
            }
          } else if (f.op === 8) {
            sock.write(frame_show(8, f.payload, false));
            sock.end();
            server.close();
            return;
          }
        }
      };
      loop().catch(() => sock.destroy());
    }).catch(() => sock.destroy());
  });
  server.listen(PORT, "127.0.0.1", () => {
    console.log(`LISTEN ${PORT}`);
  });
}

/** Runs the 6-step client script against PORT. */
async function runClient() {
  const sock = net.connect(PORT, "127.0.0.1");
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("connect timeout")), STEP_TIMEOUT_MS);
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
  const { head, rest } = await read_head(sock);
  check(head.includes("101"), "HS");
  const framer = new Framer(sock);
  framer.push(rest);
  /** @param op {number} @param payload {Buffer} */
  const send = (op, payload) => sock.write(frame_show(op, payload, true));
  const seen = { pong: false, echo: false, bin: false, ping: false };
  const done = () => seen.pong && seen.echo && seen.bin && seen.ping;
  send(9, Buffer.from("c1"));
  send(1, Buffer.from("hello"));
  send(2, Buffer.from([1, 2, 3]));
  try {
    for (;;) {
      const f = frame_parse(await framer.next(), false);
      if (f.op === 9) {
        send(10, f.payload);
        if (f.payload.toString() === "s1" && !seen.ping) {
          seen.ping = true;
          check(true, "PING_S1");
        }
      } else if (f.op === 10 && f.payload.toString() === "c1" && !seen.pong) {
        seen.pong = true;
        check(true, "PONG_C1");
      } else if (f.op === 1 && f.payload.toString() === "hello" && !seen.echo) {
        seen.echo = true;
        check(true, "ECHO");
      } else if (f.op === 2 && f.payload.equals(Buffer.from([1, 2, 3])) && !seen.bin) {
        seen.bin = true;
        check(true, "BIN_ECHO");
      } else if (f.op === 8) {
        check(done(), "CLOSE");
        send(8, f.payload);
        break;
      }
      if (done()) {
        const g = frame_parse(await framer.next(), false);
        check(g.op === 8, "CLOSE");
        send(8, g.payload);
        break;
      }
    }
    console.log(`DONE ${score}/6`);
  } finally {
    sock.destroy();
  }
}

if (MODE === "server") {
  serve();
} else if (MODE === "client") {
  runClient().catch((err) => {
    if (process.exitCode !== 1) {
      console.log(`FAIL client: ${err.message}`);
      process.exitCode = 1;
    }
  });
} else {
  console.log(`FAIL usage: server|client`);
  process.exitCode = 1;
}
