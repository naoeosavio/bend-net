// Event-driven WebSocket server for ping/pong interop with Bend.
// Uses the standard `ws` library: the ON mirror of server_native.js,
// shaped after WS.server_on (~h.serve) in lib/exemplos/server_on.bend.
// Same 6-step script: accept -> ping "s1" -> pong "s1" -> ping "c1"
// (auto-pong by the lib) -> text "hello" -> echo + ping "s2" ->
// pong "s2" -> close. Stateless like server_on.bend: every step is
// identified by (opcode, payload), so no counter threads the handlers.
// Prints one line per check and DONE 6/6 (grep rule: pass = DONE
// present with no FAIL); a failed check prints FAIL and closes early.
// Needs `ws` resolvable: NODE_PATH=/tmp/wsport/node_modules
// Usage: NODE_PATH=/tmp/wsport/node_modules node server_on.js [port]
// (default port 19880)

import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const WebSocket = require("ws");
const { WebSocketServer } = WebSocket;

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

/** Runs the stateless 6-step script for one connection.
 *
 * @param ws {import("ws").WebSocket} - The peer socket.
 */
function run_session(ws) {
  check(true, "HS", "accepted");
  ws.ping("s1");

  ws.on("pong", (data) => {
    if (data.equals(Buffer.from("s1"))) {
      check(true, "PONG_S1", `payload=${data}`);
    } else if (data.equals(Buffer.from("s2"))) {
      check(true, "PONG_S2", `payload=${data}`);
      // The server initiates the close, like server_on.bend's OK
      // PONG_S2 branch: reply close and shut.
      ws.close();
    } else {
      check(false, "PONG", `payload=${data}`);
    }
  });

  // NOTE: `ws` answers pings with a pong automatically (same payload),
  // so the client's ping "c1" is scored here and echoed by the lib.
  ws.on("ping", (data) => {
    if (data.equals(Buffer.from("c1"))) {
      check(true, "PING_C1", `payload=${data}`);
    } else {
      check(false, "PING", `payload=${data}`);
    }
  });

  ws.on("message", (data) => {
    const text = data.toString();
    if (text === "hello") {
      check(true, "TEXT", `message=${JSON.stringify(text)}`);
      ws.send("hello");
      ws.ping("s2");
    } else {
      check(false, "TEXT", `message=${JSON.stringify(text)}`);
    }
  });

  ws.on("close", () => {
    check(true, "CLOSE", "handshake done");
    console.log(`DONE ${score}/6`);
    wss.close();
  });
}

const wss = new WebSocketServer({ host: "127.0.0.1", port: PORT }, () => {
  console.log(`LISTEN ${PORT}`);
});

let session_taken = false;

wss.on("connection", (ws) => {
  if (session_taken) {
    // A second connection (a retry, a probe) is rejected; terminate
    // can throw on a half-open socket, so guard it: the running
    // session must survive either way.
    try {
      ws.terminate();
    } catch {
      // half-open socket already gone — nothing to do here
    }
    return;
  }
  session_taken = true;
  const guard = setTimeout(() => {
    console.log("FAIL session: timeout");
    process.exitCode = 1;
    try {
      ws.terminate();
    } catch {
      // socket already gone — nothing to do here
    }
    wss.close();
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
    try {
      ws.terminate();
    } catch {
      // socket already gone — nothing to do here
    }
    wss.close();
  }
});
