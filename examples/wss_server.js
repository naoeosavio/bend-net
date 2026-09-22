// TLS WebSocket echo server for interop with Bend WSS and with
// examples/wss_client.js. Uses `ws` over node:https with the test
// PEMs (tests/io/tls_test_*). One session: accept -> text "hello"
// echoed -> close. Prints LISTEN then DONE n/n (grep rule: pass =
// DONE present with no FAIL). Manual only — not in check.sh.
// Needs `ws` under node: NODE_PATH=/tmp/wsport/node_modules
// Usage: NODE_PATH=/tmp/wsport/node_modules node wss_server.js [port]
//        NODE_PATH=/tmp/wsport/node_modules bun wss_server.js [port]
// (default port 19891)

import { createRequire } from "node:module";
import { createServer } from "node:https";
import { readFileSync } from "node:fs";

// node: `ws` package for WebSocket.Server (NODE_PATH=/tmp/wsport/node_modules).
// bun: native WebSocket has no Server class — keep using `ws` (works as
// server side even under bun; only the client path needed native WebSocket).
const require = createRequire(import.meta.url);
const WebSocket = require("ws");

const PORT = Number(process.argv[2] ?? 19891);
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
  ws.on("message", (data) => {
    const text = data.toString();
    if (text === "hello") {
      check(true, "TEXT", `message=${JSON.stringify(text)}`);
      ws.send("hello");
    } else {
      check(false, "TEXT", `message=${JSON.stringify(text)}`);
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
