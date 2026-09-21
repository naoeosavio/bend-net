// Event-driven WebSocket server for ping/pong interop with Bend.
// Uses the standard `ws` library: the ON mirror of server_native.js,
// shaped after WS.server_on (~h.serve) in examples/server_on.bend.
// Same 6-step script: accept -> ping "s1" -> pong "s1" -> ping "c1"
// (auto-pong by the lib) -> text "hello" -> echo + ping "s2" ->
// pong "s2" -> close. Stateless like server_on.bend: every step is
// identified by (opcode, payload), so no counter threads the handlers.
// Prints one line per check and DONE 6/6 (grep rule: pass = DONE
// present with no FAIL); a failed check prints FAIL and closes early.
// Needs `ws` resolvable under node: NODE_PATH=/tmp/wsport/node_modules
// Usage: NODE_PATH=/tmp/wsport/node_modules node server_on.js [port]
//        bun server_on.js [port]
// (default port 19880)

import { createRequire } from "node:module";

// bun provides a global require; node ESM does not, so build one
// there from the npm ws resolvable via NODE_PATH.
const require = globalThis.require ?? createRequire(import.meta.url);
const WebSocket = require("ws");
const { WebSocketServer } = WebSocket;

const PORT = Number(process.argv[2] ?? 19880);
const SESSION_TIMEOUT_MS = 15000;

let score = 0;
// Live session handles for the failure path below. The server takes a
// single session (see session_taken), so module-level handles are enough.
let active_ws = null;
let active_guard = null;

/**
 * Shuts the session down after a failure without throwing out of
 * an event-emitter callback (a throw there would be uncaught and
 * crash the process with a stack on top of the FAIL line).
 */
function fail_session(message) {
  console.log(message);
  process.exitCode = 1;
  if (active_guard !== null) {
    clearTimeout(active_guard);
  } else {
    // timer not armed yet — nothing to do here
  }
  if (active_ws !== null) {
    try {
      active_ws.terminate();
    } catch {
      // socket already gone — nothing to do here
    }
  } else {
    // no live socket — nothing to do here
  }
  wss.close();
}

/**
 * Fails the session unless `cond` holds.
 *
 * @param cond {boolean} - The check result.
 * @param name - Check label for the log.
 * @param detail - Extra context on failure.
 */
function check(cond, name, detail) {
  if (!cond) {
    fail_session(`FAIL ${name}: ${detail}`);
  } else {
    score += 1;
    console.log(`OK ${name}`);
  }
}

/** Runs the stateless 6-step script for one connection.
 *
 * @param ws {import("ws").WebSocket} - The peer socket.
 * @param guard {NodeJS.Timeout} - The per-session timeout to clear on close.
 */
function run_session(ws, guard) {
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
    clearTimeout(guard);
    if (process.exitCode === 1) {
      // a FAIL was already logged — no DONE here
      wss.close();
      return;
    }
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
  active_ws = ws;
  active_guard = guard;
  try {
    run_session(ws, guard);
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
