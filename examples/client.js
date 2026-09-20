// Scripted WebSocket client for ping/pong interop with Bend.
// Uses the standard `ws` library (no hand-rolled framing).
// Script (6 checks): connect -> ping "s1" (auto-pong by the lib,
// no manual reply) -> ping "c1" -> pong "c1" -> text "hello" ->
// echo -> ping "s2" (auto-pong) -> server close (auto-reply).
// Prints one line per check and DONE n/6.
// Needs `ws` resolvable: NODE_PATH=/tmp/wsport/node_modules
// Usage: NODE_PATH=/tmp/wsport/node_modules node client.js [port]
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
    const cleanup = () => {
      clearTimeout(timer);
      for (const n of names) {
        ws.removeAllListeners(n);
      }
    };
    for (const n of names) {
      ws.once(n, (...args) => {
        cleanup();
        resolve({ name: n, data: args[0], code: args[1] });
      });
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
    // Awaits the hoisted listener: a second once("ping") here could
    // be removed by the first one's cleanup during emit.
    let ev = await ping_s1;
    check(ev.data.equals(Buffer.from("s1")), "PING_S1", `payload=${ev.data}`);

    ws.ping("c1");
    ev = await next_event(ws, ["pong"]);
    check(ev.data.equals(Buffer.from("c1")), "PONG_C1", `payload=${ev.data}`);

    ws.send("hello");
    ev = await next_event(ws, ["message"]);
    const text = ev.data.toString();
    check(text === "hello", "ECHO", `message=${JSON.stringify(text)}`);

    ev = await next_event(ws, ["ping"]);
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
