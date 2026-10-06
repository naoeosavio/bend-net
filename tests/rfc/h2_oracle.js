// H2 oracle: HTTPS echo for RFC 9113/7541 conformance. Builtins only
// (node:http2, node:fs), so the same file runs under node and bun.
// Two modes:
//   node h2_oracle.js server [port] [n]  — echo server, DONE n/n
//   node h2_oracle.js client <port>       — one-shot check vs any
//     server (Bend or this oracle), DONE 1/1
// The server takes both lanes: `request` (HTTP/1.1 fallback) and
// `stream` (h2). The client speaks h2 and posts "hello" to /echo.
import { createSecureServer, connect } from "node:http2";
import { readFileSync } from "node:fs";

const MODE = process.argv[2] ?? "server";
const PORT = Number(process.argv[3] ?? 19883);
const DONE_AFTER = Number(process.argv[4] ?? 1);
const CERT = readFileSync("tests/io/tls_test_cert.pem");
const KEY = readFileSync("tests/io/tls_test_key.pem");

let score = 0;
let exchanges = 0;

/**
 * Fails the run unless `cond` holds.
 *
 * @param cond {boolean} - The check result.
 * @param name {string} - Check label for the log.
 */
function check(cond, name) {
  if (!cond) {
    console.log(`FAIL ${name}`);
    process.exitCode = 1;
    throw new Error(`FAIL ${name}`);
  }
  score += 1;
  console.log(`OK ${name}`);
}

/** Counts one answered exchange toward DONE. */
function counted(server, path, len) {
  console.log(`OK ECHO path=${path} len=${len}`);
  exchanges += 1;
  if (exchanges >= DONE_AFTER) {
    console.log(`DONE ${exchanges}/${DONE_AFTER}`);
    server.close();
  }
}

/** Starts the echo server on both lanes. */
function serve() {
  const server = createSecureServer({ key: KEY, cert: CERT, allowHTTP1: true });
  server.on("error", (err) => {
    console.log(`FAIL server: ${err.message}`);
    process.exitCode = 1;
  });
  server.on("request", (req, res) => {
    if (req.httpVersion === "2.0") {
      return;
    }
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      res.writeHead(200, { "content-length": String(body.length) });
      res.end(body);
      counted(server, req.url, body.length);
    });
  });
  server.on("stream", (stream, headers) => {
    const chunks = [];
    stream.on("data", (c) => chunks.push(c));
    stream.on("end", () => {
      const body = Buffer.concat(chunks);
      stream.respond({ ":status": 200, "content-length": String(body.length) });
      stream.end(body);
      counted(server, headers[":path"], body.length);
    });
  });
  server.listen(PORT, "127.0.0.1", () => {
    console.log(`LISTEN ${PORT}`);
  });
}

/** Runs the one-shot h2 client script against PORT. */
async function runClient() {
  const client = connect(`https://127.0.0.1:${PORT}`, {
    rejectUnauthorized: false,
  });
  await new Promise((resolve, reject) => {
    client.on("error", reject);
    client.on("connect", resolve);
  });
  const req = client.request({
    ":method": "POST",
    ":path": "/echo",
  });
  req.end("hello");
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  await new Promise((resolve) => req.on("end", resolve));
  const body = Buffer.concat(chunks).toString();
  check(body === "hello", "ECHO");
  console.log(`DONE ${score}/1`);
  client.close();
}

if (MODE === "server") {
  serve();
} else if (MODE === "client") {
  runClient().catch((err) => {
    if (process.exitCode !== 1) {
      console.log(`FAIL client: ${err.message}`);
      process.exitCode = 1;
    }
  });
} else {
  console.log(`FAIL usage: server|client`);
  process.exitCode = 1;
}
