// Scripted WebSocket server for ping/pong interop with Bend.
// Uses the standard `ws` library (no hand-rolled framing).
// Script (6 checks): accept -> ping "s1" -> pong "s1" ->
// ping "c1" -> auto-pong -> text "hello" -> echo + ping "s2" ->
// pong "s2" -> close. Prints one line per check and DONE n/6.
// Needs `ws` resolvable under node: NODE_PATH=/tmp/wsport/node_modules
// Usage: NODE_PATH=/tmp/wsport/node_modules node server.js [port]
//        bun server.js [port]
// (default port 19880)

import { createRequire } from "node:module";

// bun provides a global require; node ESM does not, so build one
// there from the npm ws resolvable via NODE_PATH.
const require = globalThis.require ?? createRequire(import.meta.url);
const { WebSocketServer } = require("ws");

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

const wss = new WebSocketServer({ host: "127.0.0.1", port: PORT }, () => {
  console.log(`LISTEN ${PORT}`);
});

let session_taken = false;

wss.on("connection", (ws) => {
  if (session_taken) {
    // A second connection (a retry, a probe) is rejected; terminate
    // can throw on a half-open socket (Bun's ws does), so guard it:
    // the running session must survive either way.
    try {
      ws.terminate();
    } catch {
      // half-open socket already gone — nothing to do here
    }
    return;
  }
  session_taken = true;
  run_session(ws).catch((err) => {
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
  });
});

/** @param ws {import("ws").WebSocket} */
async function run_session(ws) {
  check(true, "HS", "accepted");

  ws.ping("s1");
  let ev = await next_event(ws, ["pong"]);
  check(ev.data.equals(Buffer.from("s1")), "PONG_S1", `payload=${ev.data}`);

  ev = await next_event(ws, ["ping"]);
  check(ev.data.equals(Buffer.from("c1")), "PING_C1", `payload=${ev.data}`);
  // NOTE: `ws` answers pings with a pong automatically.

  ev = await next_event(ws, ["message"]);
  const text = ev.data.toString();
  check(text === "hello", "TEXT", `message=${JSON.stringify(text)}`);
  ws.send("hello");
  console.log("SENT echo");
  ws.ping("s2");

  ev = await next_event(ws, ["pong"]);
  check(ev.data.equals(Buffer.from("s2")), "PONG_S2", `payload=${ev.data}`);

  // Hoists the close waiter before the close action (like ping_s1 on
  // the client): some shims emit "close" synchronously on close(),
  // and a listener attached after would miss it and time out.
  const closed = next_event(ws, ["close"]);
  ws.close();
  ev = await closed;
  check(true, "CLOSE", `code=${ev.data}`);

  console.log(`DONE ${score}/6`);
  wss.close();
}
