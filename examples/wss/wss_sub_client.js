// TLS WebSocket subprotocol client for interop with
// examples/wss/wsm_sub_echo.bend (Bend WSM.server_on_sub ["p1"]).
// Offers ['p1','p2'], sends "hello", expects echo, closes.
// Prints DONE n/n (grep rule: pass = DONE present with no FAIL).
// Manual only — not in check.sh.
// Usage: NODE_PATH=/tmp/wsport/node_modules node wss_sub_client.js [port]
// (default port 19894)
import { createRequire } from "node:module";

const is_bun = typeof Bun !== "undefined";
const WebSocket = is_bun
  ? globalThis.WebSocket
  : createRequire(import.meta.url)("ws");

const PORT = Number(process.argv[2] ?? 19894);
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

const ws = new WebSocket(`wss://127.0.0.1:${PORT}/chat`, ["p1", "p2"], {
  rejectUnauthorized: false,
  tls: { rejectUnauthorized: false },
});

ws.addEventListener("open", () => {
  clearTimeout(guard);
  const proto = ws.protocol ?? "";
  check(true, "HS", "connected");
  check(proto === "p1", "PROTO", `protocol=${JSON.stringify(proto)}`);
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
  if (score === 0) {
    console.log("FAIL session: closed before open");
    process.exitCode = 1;
    return;
  }
  check(true, "CLOSE", "handshake done");
  console.log(`DONE ${score}/4`);
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
