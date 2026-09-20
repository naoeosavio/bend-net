// Scripted WebSocket server for ping/pong interop with Bend.
// Uses the standard `ws` library (no hand-rolled framing).
// Script (6 checks): accept -> ping "s1" -> pong "s1" ->
// ping "c1" -> auto-pong -> text "hello" -> echo + ping "s2" ->
// pong "s2" -> close. Prints one line per check and DONE n/6.
// Needs `ws` resolvable: NODE_PATH=/tmp/wsport/node_modules
// Usage: NODE_PATH=/tmp/wsport/node_modules node server.js [port]
// (default port 19880)

import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { WebSocketServer } = require("ws");

const PORT = Number(process.argv[2] ?? 19880);
const STEP_TIMEOUT_MS = 5000;

// Pacing between back-to-back server writes. Bend reads with
// single-shot TCP.recv and has no framing layer, so two frames in
// one segment would merge into a single read. 100ms >> localhost
// RTT: the client always consumes the first frame before the
// second hits the wire.
const PACE_MS = 100;

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
    ws.terminate();
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

  await sleep(PACE_MS);
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
  await sleep(PACE_MS);
  ws.ping("s2");

  ev = await next_event(ws, ["pong"]);
  check(ev.data.equals(Buffer.from("s2")), "PONG_S2", `payload=${ev.data}`);

  ws.close();
  ev = await next_event(ws, ["close"]);
  check(true, "CLOSE", `code=${ev.data}`);

  console.log(`DONE ${score}/6`);
  wss.close();
}
