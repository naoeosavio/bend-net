// Minimal H2-only echo for HTTPX client_once interop (no compat 'request'
// handler, so no double-respond). Prints LISTEN, echoes body, DONE.
import { createSecureServer } from "node:http2";
import { readFileSync } from "node:fs";

const PORT = Number(process.argv[2] ?? 19893);
const DONE_AFTER = Number(process.argv[3] ?? 1);
const CERT = readFileSync("tests/io/tls_test_cert.pem");
const KEY = readFileSync("tests/io/tls_test_key.pem");

let exchanges = 0;
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
    stream.respond({ ":status": 200, "content-length": String(body.length) });
    stream.end(body);
    console.log(`OK ECHO path=${headers[":path"]} len=${body.length}`);
    exchanges += 1;
    if (exchanges >= DONE_AFTER) {
      console.log(`DONE ${exchanges}/${DONE_AFTER}`);
      server.close();
    }
  });
});
server.listen(PORT, "127.0.0.1", () => {
  console.log(`LISTEN ${PORT}`);
});
