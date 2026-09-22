// TLS WebSocket client for interop with examples/wss_server.js and
// with Bend WSS.client_echo_insecure / client_on_insecure. Connects
// wss://127.0.0.1 with rejectUnauthorized:false (test PEM, no CA).
// Script: connect -> send "hello" -> echo -> close. Prints DONE n/n
// (grep rule: pass = DONE present with no FAIL). Manual only — not
// in check.sh. Node needs `ws`: NODE_PATH=/tmp/wsport/node_modules.
// Bun uses native WebSocket (ws package TLS-fails under bun).
// Usage: NODE_PATH=/tmp/wsport/node_modules node wss_client.js [port]
//        bun wss_client.js [port]
// (default port 19891)

import { createRequire } from "node:module";

// bun: native WebSocket + tls.rejectUnauthorized (ws package fails TLS
// handshake 1015 under bun against the self-signed test PEM).
// node: `ws` package (needs NODE_PATH=/tmp/wsport/node_modules).
const is_bun = typeof Bun !== "undefined";
const WebSocket = is_bun
  ? globalThis.WebSocket
  : createRequire(import.meta.url)("ws");

const PORT = Number(process.argv[2] ?? 19891);
const SESSION_TIMEOUT_MS = 15000;

let score = 0;
let end = null;

function fail_session(message) {
  console.log(message);
  process.exitCode = 1;
  clearTimeout(guard);
  if (end !== null) {
    clearTimeout(end);
  }
  try {
    if (typeof ws.terminate === "function") {
      ws.terminate();
    } else {
      ws.close();
    }
  } catch {
    // socket already gone — nothing to do here
  }
}

function check(cond, name, detail) {
  if (!cond) {
    fail_session(`FAIL ${name}: ${detail}`);
  } else {
    score += 1;
    console.log(`OK ${name}`);
  }
}

const ws = new WebSocket(`wss://127.0.0.1:${PORT}/chat`, {
  // node `ws`: top-level; bun native WebSocket: nested under tls
  rejectUnauthorized: false,
  tls: { rejectUnauthorized: false },
});

ws.addEventListener("open", () => {
  clearTimeout(guard);
  check(true, "HS", "connected");
  ws.send("hello");
  end = setTimeout(() => {
    console.log("FAIL session: timeout");
    process.exitCode = 1;
    process.exit(1);
  }, SESSION_TIMEOUT_MS);
  end.unref();
});

ws.addEventListener("message", (event) => {
  const raw = event.data ?? event;
  const text = typeof raw === "string" ? raw : String(raw);
  if (text === "hello") {
    check(true, "ECHO", `message=${JSON.stringify(text)}`);
    ws.close();
  } else {
    check(false, "TEXT", `message=${JSON.stringify(text)}`);
  }
});

ws.addEventListener("close", () => {
  if (end !== null) {
    clearTimeout(end);
  }
  if (process.exitCode === 1) {
    return;
  }
  // CLOSE without OPEN means the handshake never finished — fail.
  if (score === 0) {
    console.log("FAIL session: closed before open");
    process.exitCode = 1;
    return;
  }
  check(true, "CLOSE", "handshake done");
  console.log(`DONE ${score}/3`);
});

ws.addEventListener("error", (event) => {
  if (process.exitCode !== 1) {
    const message = event?.message ?? event?.error?.message ?? "socket error";
    console.log(`FAIL session: ${message}`);
    process.exitCode = 1;
  }
});

const guard = setTimeout(() => {
  console.log("FAIL session: timeout");
  process.exitCode = 1;
  try {
    if (typeof ws.terminate === "function") {
      ws.terminate();
    } else {
      ws.close();
    }
  } catch {
    // socket already gone — nothing to do here
  }
}, SESSION_TIMEOUT_MS);
guard.unref();
