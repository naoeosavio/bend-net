// Event-driven WebSocket client for ping/pong interop with Bend.
// Uses the standard `ws` library: the ON mirror of client_native.js,
// shaped after WS.client_on (~h.cl) in examples/cliente_on.bend.
// Same 6-step script: connect -> ping "s1" (auto-pong by the lib) ->
// ping "c1" / pong "c1" -> text "hello" -> echo -> ping "s2"
// (auto-pong) -> server close. Stateless like cliente_on.bend: every
// step is identified by (opcode, payload), so no counter threads the
// handlers. Prints one line per check and DONE 6/6 (grep rule: pass =
// DONE present with no FAIL); a failed check prints FAIL and exits.
// Needs `ws` resolvable under node: NODE_PATH=/tmp/wsport/node_modules
// (under bun, require("ws") answers the builtin — no path needed there).
// Usage: NODE_PATH=/tmp/wsport/node_modules node client_on.js [port]
//        bun client_on.js [port]
// (default port 19880)

import { createRequire } from "node:module";

// bun provides a global require; node ESM does not, so build one
// there from the npm ws resolvable via NODE_PATH.
const require = globalThis.require ?? createRequire(import.meta.url);
const WebSocket = require("ws");

// Bun's builtin reimplementation defers its automatic pong to the next
// macrotask, so a synchronous send in the ping handler hits the wire
// BEFORE the pong (npm queues it before emit; probes x5 each, see
// task-012). Strictly sequential servers read pong "s1" as frame#1, so
// the user ping is deferred one tick under bun: same wire order as npm.
// (The handlers here are attached once with on() and never removed, so
// the builtin's once()-poisoning bug does not apply to this file.)
const BUN = String(WebSocket).includes("BunWebSocket");

const PORT = Number(process.argv[2] ?? 19880);
const SESSION_TIMEOUT_MS = 15000;

let score = 0;
// Armed on open; cleared on close so a late timeout can never fail
// a session that already printed DONE.
let end = null;

/**
 * Shuts the session down after a failure without throwing out of
 * an event-emitter callback (a throw there would be uncaught and
 * crash the process with a stack on top of the FAIL line).
 */
function fail_session(message) {
  console.log(message);
  process.exitCode = 1;
  clearTimeout(guard);
  if (end !== null) {
    clearTimeout(end);
  } else {
    // timer not armed yet — nothing to do here
  }
  try {
    ws.terminate();
  } catch {
    // socket already gone — nothing to do here
  }
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

const ws = new WebSocket(`ws://127.0.0.1:${PORT}/chat`);

// The first ping may already be on the wire when open fires (a fast
// server sends it right after the handshake), so the handlers go on
// before the open wait: otherwise the event is missed. This is harness
// ordering, not pacing.
// NOTE on labels: a received ping "s1"/"s2" is logged as PONG_S1/PONG_S2,
// mirroring WS.client_on (~h.cl) in examples/cliente_on.bend (which logs
// "OK PONG_S1" on EvPing). The classic client.js instead logs PING_S1;
// both mean "ping s1 arrived, the lib auto-ponged".
ws.on("ping", (data) => {
  // NOTE: `ws` answers pings with a pong automatically (same payload),
  // so the server scores the pong; "c1" waits below via the pong event.
  if (data.equals(Buffer.from("s1"))) {
    check(true, "PONG_S1", `payload=${data}`);
    // Under bun the auto-pong for s1 is deferred (see BUN above): the
    // send waits one tick so the pong wins the wire, like npm does.
    if (BUN) {
      setTimeout(() => ws.ping("c1"), 0);
    } else {
      ws.ping("c1");
    }
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
  if (end !== null) {
    clearTimeout(end);
  } else {
    // session ended before open armed the timer — nothing to do here
  }
  if (process.exitCode === 1) {
    // a FAIL was already logged — no DONE here
    return;
  }
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
  end = setTimeout(() => {
    console.log("FAIL session: timeout");
    process.exitCode = 1;
    process.exit(1);
  }, SESSION_TIMEOUT_MS);
  end.unref();
});
