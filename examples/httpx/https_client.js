// HTTP/2 secure client (node:http2) for interop with Bend HTTPS
// servers (HTTPS.server_on / server_on_concurrent). Connects
// 127.0.0.1 with rejectUnauthorized:false (test PEM, no CA), sends
// one POST "hello" and checks the echo. Prints DONE n/n (grep rule:
// pass = DONE present with no FAIL). Manual only — not in check.sh.
// Usage: node https_client.js [port]
//        bun https_client.js [port]
// (default port 19892)

import { connect } from "node:http2";

const PORT = Number(process.argv[2] ?? 19892);
const SESSION_TIMEOUT_MS = 15000;

let score = 0;
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

client.on("connect", () => {
  clearTimeout(guard);
  check(true, "HS", "connected");
  end = setTimeout(() => {
    console.log("FAIL session: timeout");
    process.exitCode = 1;
    process.exit(1);
  }, SESSION_TIMEOUT_MS);
  end.unref();

  const req = client.request({ ":path": "/echo", ":method": "POST" });
  const chunks = [];
  req.on("response", (headers) => {
    check(headers[":status"] === 200, "STATUS", `status=${headers[":status"]}`);
  });
  req.on("error", (err) => {
    // Node→Bend may 502 on huffman HPACK — surface it as FAIL, not hang.
    if (process.exitCode !== 1) {
      console.log(`FAIL request: ${err.message}`);
      process.exitCode = 1;
    }
  });
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.isBuffer(chunks[0]) || chunks[0] instanceof Uint8Array
      ? Buffer.concat(chunks).toString()
      : chunks.join("");
    check(body === "hello", "ECHO", `body=${JSON.stringify(body)}`);
    if (end !== null) {
      clearTimeout(end);
    }
    if (process.exitCode === 1) {
      client.close();
      return;
    }
    check(true, "CLOSE", "exchange done");
    console.log(`DONE ${score}/4`);
    client.close();
  });
  req.end("hello");
});
