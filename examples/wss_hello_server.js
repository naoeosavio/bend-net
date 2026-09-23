// TLS WebSocket coalesce probe for Bend WSS interop (task-020 phase 0).
// Unlike examples/wss_server.js (waits for the client first), this peer
// sends "hello" inside the `connection` callback, so the 101 and the
// first frame coalesce in one TCP segment — the case that used to lose
// 3 frame bytes to the client_scan_len off-by-3. Then it echoes.
// Prints LISTEN then DONE n/n (grep rule: pass = DONE present with no
// FAIL). Manual only — not in check.sh.
// Needs `ws` under node: NODE_PATH=/tmp/wsport/node_modules
// Usage: NODE_PATH=/tmp/wsport/node_modules node wss_hello_server.js [port]
//        (default port 19892)
// Pair with: bend examples/wss_hello_client.bend (expects "hello" -> 1)

import { createRequire } from "node:module";
import { createServer } from "node:https";
import { readFileSync } from "node:fs";

const require = createRequire(import.meta.url);
const WebSocket = require("ws");

const PORT = Number(process.argv[2] ?? 19892);
const CERT = readFileSync("tests/io/tls_test_cert.pem");
const KEY = readFileSync("tests/io/tls_test_key.pem");
const SESSION_TIMEOUT_MS = 15000;

let score = 0;
let session_taken = false;
let guard = null;

function fail_session(message) {
  console.log(message);
  process.exitCode = 1;
  if (guard !== null) {
    clearTimeout(guard);
  }
  wss.close();
  server.close();
}

function check(cond, name, detail) {
  if (!cond) {
    fail_session(`FAIL ${name}: ${detail}`);
  } else {
    score += 1;
    console.log(`OK ${name}`);
  }
}

function run_session(ws) {
  check(true, "HS", "accepted");
  // Immediate send: rides the same segment as the 101 handshake.
  ws.send("hello");
  ws.on("message", (data) => {
    const text = data.toString();
    if (text === "hello") {
      check(true, "ECHO", `message=${JSON.stringify(text)}`);
      ws.close();
    } else {
      check(false, "ECHO", `message=${JSON.stringify(text)}`);
    }
  });
  ws.on("close", () => {
    clearTimeout(guard);
    if (process.exitCode === 1) {
      wss.close();
      server.close();
      return;
    }
    check(true, "CLOSE", "session done");
    console.log(`DONE ${score}/3`);
    wss.close();
    server.close();
  });
}

const server = createServer({ cert: CERT, key: KEY });
const wss = new WebSocket.Server({ server });

wss.on("connection", (ws) => {
  if (session_taken) {
    try {
      ws.terminate();
    } catch {
      // half-open socket already gone — nothing to do here
    }
    return;
  }
  session_taken = true;
  guard = setTimeout(() => {
    console.log("FAIL session: timeout");
    process.exitCode = 1;
    try {
      ws.terminate();
    } catch {
      // socket already gone — nothing to do here
    }
    wss.close();
    server.close();
  }, SESSION_TIMEOUT_MS);
  guard.unref();
  try {
    run_session(ws);
  } catch (err) {
    clearTimeout(guard);
    if (process.exitCode !== 1) {
      console.log(`FAIL session: ${err.message}`);
      process.exitCode = 1;
    }
    wss.close();
    server.close();
  }
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`LISTEN ${PORT}`);
});
