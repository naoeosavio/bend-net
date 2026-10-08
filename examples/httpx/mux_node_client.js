// HTTPX node interop: N concurrent POSTs on ONE node:http2 session
// against the mini-H2 echo server (examples/httpx/httpx_echoserv.bend).
// Each request sends "hello-i" and expects status 200 + same echo.
// Prints DONE n/N (grep rule: pass = DONE present with no FAIL).
// Manual only — not in check.sh.
// Usage: node mux_node_client.js [port] [n]
//        bun mux_node_client.js [port] [n]
// (defaults port 19892, n 4)

import { connect } from "node:http2";

const PORT = Number(process.argv[2] ?? 19892);
const N = Number(process.argv[3] ?? 4);
const SESSION_TIMEOUT_MS = 15000;

let score = 0;
let done = 0;
let end = null;

function fail_session(message) {
  console.log(message);
  process.exitCode = 1;
  clearTimeout(guard);
  if (end !== null) {
    clearTimeout(end);
  }
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
  // node http2: top-level; some bun paths want nested tls
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

function finish() {
  done += 1;
  if (done === N) {
    clearTimeout(guard);
    if (end !== null) {
      clearTimeout(end);
    }
    if (process.exitCode === 1) {
      client.close();
      return;
    }
    check(true, "CLOSE", "exchange done");
    console.log(`DONE ${score}/${2 * N + 2}`);
    client.close();
  }
}

client.on("connect", () => {
  clearTimeout(guard);
  check(true, "HS", "connected");
  end = setTimeout(() => {
    console.log("FAIL session: timeout");
    process.exitCode = 1;
    process.exit(1);
  }, SESSION_TIMEOUT_MS);
  end.unref();

  for (let i = 0; i < N; i++) {
    const want = `hello-${i}`;
    const req = client.request({ ":path": "/echo", ":method": "POST" });
    const chunks = [];
    req.on("response", (headers) => {
      check(headers[":status"] === 200, `STATUS-${i}`, `status=${headers[":status"]}`);
    });
    req.on("error", (err) => {
      if (process.exitCode !== 1) {
        console.log(`FAIL request-${i}: ${err.message}`);
        process.exitCode = 1;
      }
      finish();
    });
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.isBuffer(chunks[0]) || chunks[0] instanceof Uint8Array
        ? Buffer.concat(chunks).toString()
        : chunks.join("");
      check(body === want, `ECHO-${i}`, `body=${JSON.stringify(body)}`);
      finish();
    });
    req.end(want);
  }
});
