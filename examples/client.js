// Scripted WebSocket client for ping/pong interop with Bend.
// Uses the standard `ws` library (no hand-rolled framing).
// Script (6 checks): connect -> ping "s1" (auto-pong by the lib,
// no manual reply) -> ping "c1" -> pong "c1" -> text "hello" ->
// echo -> ping "s2" (auto-pong) -> server close (auto-reply).
// Prints one line per check and DONE n/6.
// Needs `ws` resolvable under node: NODE_PATH=/tmp/wsport/node_modules
// (under bun, require("ws") answers the builtin — no path needed there).
// Usage: NODE_PATH=/tmp/wsport/node_modules node client.js [port]
//        bun client.js [port]
// (default port 19880)

import { createRequire } from "node:module";

// bun provides a global require; node ESM does not, so build one
// there from the npm ws resolvable via NODE_PATH.
const require = globalThis.require ?? createRequire(import.meta.url);
const WebSocket = require("ws");

// Bun's builtin reimplementation differs from npm in two ways (probes
// x4/x5 each, see task-012): its automatic pong is deferred to the next
// macrotask, so a synchronous send in the ping handler hits the wire
// BEFORE the pong (npm queues it before emit); and once() poisons the
// "ping" event path for re-attached listeners when the first ping
// listener was a once. next_event() below attaches with on() always,
// and the user ping is deferred one tick under bun: both together give
// the same wire order and event behavior as npm (matrix 6/6, task-012).
const BUN = String(WebSocket).includes("BunWebSocket");

const PORT = Number(process.argv[2] ?? 19880);
const STEP_TIMEOUT_MS = 5000;

/** @param ms {number} */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

let score = 0;

/**
 * Waits for the next event in `names` on `ws`, rejecting on timeout.
 *
 * @param ws {import("ws").WebSocket} - The peer socket.
 * @param names {string[]} - Event names to race.
 * @returns The event name and payload.
 */
function next_event(ws, names) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`timeout waiting for ${names.join("/")}`));
    }, STEP_TIMEOUT_MS);
    // Bun's builtin poisons the "ping" event path for re-attached
    // listeners when the FIRST ping listener was attached with once()
    // (auto-removed after firing): later listeners never fire, while
    // the auto-pong keeps working (probe x4, task-012). Attaching with
    // on() and removing surgically is equivalent and works everywhere.
    const handlers = {};
    const cleanup = () => {
      clearTimeout(timer);
      for (const n of names) {
        ws.removeListener(n, handlers[n]);
      }
    };
    for (const n of names) {
      const handler = (...args) => {
        cleanup();
        resolve({ name: n, data: args[0], code: args[1] });
      };
      handlers[n] = handler;
      ws.on(n, handler);
    }
  });
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
    console.log(`FAIL ${name}: ${detail}`);
    process.exitCode = 1;
    throw new Error(`FAIL ${name}`);
  }
  score += 1;
  console.log(`OK ${name}`);
}

/** Runs the 6-step script against the server at PORT. */
async function main() {
  const ws = new WebSocket(`ws://127.0.0.1:${PORT}/chat`);
  // The first ping may already be on the wire when open fires (a fast
  // server sends it right after the handshake), so the listener goes
  // on before the open wait: otherwise the event is missed and the
  // step times out. This is harness ordering, not pacing.
  const ping_s1 = next_event(ws, ["ping"]);
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error("timeout waiting for open"));
    }, STEP_TIMEOUT_MS);
    ws.once("open", () => {
      clearTimeout(timer);
      resolve();
    });
    ws.once("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
  check(true, "HS", "connected");
  try {
    // NOTE: `ws` answers pings with a pong automatically, so the
    // client only waits here; the server scores its pong.
    // Awaits the hoisted listener: its handler is already registered,
    // so an early ping is not lost.
    let ev = await ping_s1;
    check(ev.data.equals(Buffer.from("s1")), "PING_S1", `payload=${ev.data}`);

    // Under bun the auto-pong for s1 is deferred (see BUN above): the
    // send waits one tick so the pong wins the wire, like npm does.
    if (BUN) {
      setTimeout(() => ws.ping("c1"), 0);
    } else {
      ws.ping("c1");
    }
    ev = await next_event(ws, ["pong"]);
    check(ev.data.equals(Buffer.from("c1")), "PONG_C1", `payload=${ev.data}`);

    ws.send("hello");
    // The peer may glue echo + ping s2 in a single write (server_on
    // answers both in one WSOut): hoist the ping waiter before the
    // message wait, like ping_s1 above, so an early ping is not lost.
    const ping_s2 = next_event(ws, ["ping"]);
    ev = await next_event(ws, ["message"]);
    const text = ev.data.toString();
    check(text === "hello", "ECHO", `message=${JSON.stringify(text)}`);

    ev = await ping_s2;
    check(ev.data.equals(Buffer.from("s2")), "PING_S2", `payload=${ev.data}`);
    // NOTE: `ws` ponged automatically; the server scores it.

    ev = await next_event(ws, ["close"]);
    check(true, "CLOSE", `code=${ev.data}`);

    console.log(`DONE ${score}/6`);
  } catch (err) {
    if (process.exitCode !== 1) {
      console.log(`FAIL session: ${err.message}`);
      process.exitCode = 1;
    }
  } finally {
    try {
      ws.terminate();
    } catch {
      // socket already gone — nothing to do here
    }
  }
}

await main();
