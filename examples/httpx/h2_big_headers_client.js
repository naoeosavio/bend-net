// HTTP/2 big-headers client (node:http2) for Phase 4 interop: sends a
// ~25KB header block (forces HEADERS + CONTINUATION on the wire) plus
// a session PING against a Bend HTTPS.server_on peer, then a small
// POST echo. Prints DONE n/n (grep rule: pass = DONE with no FAIL).
// Manual only — not in check.sh.
// Usage: node h2_big_headers_client.js [port]   (default 19893)
import { connect } from "node:http2";

const PORT = Number(process.argv[2] ?? 19893);
const SESSION_TIMEOUT_MS = 30000;

let score = 0;

function fail_session(message) {
  console.log(message);
  process.exitCode = 1;
  clearTimeout(guard);
  try {
    client.close();
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

const client = connect("https://127.0.0.1:" + PORT, {
  rejectUnauthorized: false,
  tls: { rejectUnauthorized: false },
});

client.on("error", (err) => {
  if (process.exitCode !== 1) {
    console.log(`FAIL session: ${err.message}`);
    process.exitCode = 1;
  }
});

const guard = setTimeout(() => {
  console.log("FAIL session: timeout");
  process.exitCode = 1;
  try {
    client.close();
  } catch {
    // socket already gone — nothing to do here
  }
}, SESSION_TIMEOUT_MS);
guard.unref();

client.on("connect", () => {
  clearTimeout(guard);
  check(true, "HS", "connected");
  client.ping((err, duration, payload) => {
    if (err) {
      fail_session(`FAIL PING: ${err.message}`);
      return;
    }
    check(true, "PING", `ack rtt=${duration}ms`);
    sendBig();
  });
});

function sendBig() {
  const headers = { ":path": "/echo", ":method": "POST" };
  for (let i = 0; i < 25; i += 1) {
    headers["x-pad-" + i] = "a".repeat(1024);
  }
  const req = client.request(headers);
  const chunks = [];
  req.on("response", (hdrs) => {
    check(hdrs[":status"] === 200, "STATUS", `status=${hdrs[":status"]}`);
  });
  req.on("error", (err) => {
    if (process.exitCode !== 1) {
      console.log(`FAIL request: ${err.message}`);
      process.exitCode = 1;
    }
  });
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(chunks).toString();
    check(body === "hi", "ECHO", `body=${JSON.stringify(body).slice(0, 60)}`);
    if (process.exitCode === 1) {
      client.close();
      return;
    }
    check(true, "CLOSE", "exchange done");
    console.log(`DONE ${score}/5`);
    client.close();
  });
  req.end("hi");
}
