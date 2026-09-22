// HTTP/2 secure echo server (node:http2) for interop with Bend
// HTTPS clients (HTTPS.send_request_insecure / fetch_insecure). Uses
// the test PEMs (tests/io/tls_test_*), ALPN h2. Echoes the request
// body on any path. Prints LISTEN then DONE n/n after the first
// exchange (manual only — not in check.sh). The Node HPACK encoder
// uses huffman + dynamic table + multi-byte ints — Bend decodes all
// of that since task-019 (HPACK full); if the Bend client fails, that
// is a bug, not the old documented limitation (see README HTTPS Scope).
// Usage: node https_server.js [port]
//        bun https_server.js [port]
// (default port 19892)

import { createSecureServer } from "node:http2";
import { readFileSync } from "node:fs";

const PORT = Number(process.argv[2] ?? 19892);
const CERT = readFileSync("tests/io/tls_test_cert.pem");
const KEY = readFileSync("tests/io/tls_test_key.pem");
const DONE_AFTER = Number(process.argv[3] ?? 1);

let exchanges = 0;
let score = 0;

const server = createSecureServer({ key: KEY, cert: CERT, allowHTTP1: false });

server.on("error", (err) => {
  console.log(`FAIL server: ${err.message}`);
  process.exitCode = 1;
});

server.on("stream", (stream, headers) => {
  const chunks = [];
  stream.on("data", (c) => chunks.push(c));
  stream.on("end", () => {
    const body = Buffer.concat(chunks);
    stream.respond({
      ":status": 200,
      "content-type": "text/plain",
      "content-length": String(body.length),
    });
    stream.end(body);
    score += 1;
    console.log(`OK ECHO path=${headers[":path"]} len=${body.length}`);
    exchanges += 1;
    if (exchanges >= DONE_AFTER) {
      console.log(`DONE ${score}/${DONE_AFTER}`);
      server.close();
    }
  });
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`LISTEN ${PORT}`);
});
