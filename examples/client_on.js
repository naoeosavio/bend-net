// Event-driven WebSocket client for ping/pong interop with Bend.
// Uses the standard `ws` library: the ON mirror of client_native.js,
// shaped after WS.client_on (~h.cl) in lib/exemplos/cliente_on.bend.
// Same 6-step script: connect -> ping "s1" (auto-pong by the lib) ->
// ping "c1" / pong "c1" -> text "hello" -> echo -> ping "s2"
// (auto-pong) -> server close. Stateless like cliente_on.bend: every
// step is identified by (opcode, payload), so no counter threads the
// handlers. Prints one line per check and DONE 6/6 (grep rule: pass =
// DONE present with no FAIL); a failed check prints FAIL and exits.
// Needs `ws` resolvable: NODE_PATH=/tmp/wsport/node_modules
// Usage: NODE_PATH=/tmp/wsport/node_modules node client_on.js [port]
// (default port 19880)

import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const WebSocket = require("ws");

// Refuses Bun's builtin ws reimplementation (BunWebSocket): it loses
// frames mid-session, which surfaces as harness timeouts. Run under
// node with the npm ws resolvable (NODE_PATH=/tmp/wsport/node_modules).
if (String(WebSocket).includes("BunWebSocket")) {
  console.log("FAIL harness: BunWebSocket detected, run under node");
  process.exit(1);
}

const PORT = Number(process.argv[2] ?? 19880);
const SESSION_TIMEOUT_MS = 15000;

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

const ws = new WebSocket(`ws://127.0.0.1:${PORT}/chat`);

// The first ping may already be on the wire when open fires (a fast
// server sends it right after the handshake), so the handlers go on
// before the open wait: otherwise the event is missed. This is harness
// ordering, not pacing.
ws.on("ping", (data) => {
  // NOTE: `ws` answers pings with a pong automatically (same payload),
  // so the server scores the pong; "c1" waits below via the pong event.
  if (data.equals(Buffer.from("s1"))) {
    check(true, "PONG_S1", `payload=${data}`);
    ws.ping("c1");
  } else if (data.equals(Buffer.from("s2"))) {
    check(true, "PONG_S2", `payload=${data}`);
  } else {
    check(false, "PING", `payload=${data}`);
  }
});

ws.on("pong", (data) => {
  if (data.equals(Buffer.from("c1"))) {
    check(true, "PONG_C1", `payload=${data}`);
    ws.send("hello");
  } else {
    check(false, "PONG", `payload=${data}`);
  }
});

ws.on("message", (data) => {
  const text = data.toString();
  if (text === "hello") {
    check(true, "ECHO", `message=${JSON.stringify(text)}`);
  } else {
    check(false, "TEXT", `message=${JSON.stringify(text)}`);
  }
});

ws.on("close", () => {
  check(true, "CLOSE", "handshake done");
  console.log(`DONE ${score}/6`);
});

ws.on("error", (err) => {
  if (process.exitCode !== 1) {
    console.log(`FAIL session: ${err.message}`);
    process.exitCode = 1;
  }
});

const guard = setTimeout(() => {
  console.log("FAIL session: timeout");
  process.exitCode = 1;
  try {
    ws.terminate();
  } catch {
    // socket already gone — nothing to do here
  }
}, SESSION_TIMEOUT_MS);
guard.unref();

ws.on("open", () => {
  clearTimeout(guard);
  check(true, "HS", "connected");
  const end = setTimeout(() => {
    console.log("FAIL session: timeout");
    process.exitCode = 1;
    process.exit(1);
  }, SESSION_TIMEOUT_MS);
  end.unref();
});
