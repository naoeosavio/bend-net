// H2-only big response for HTTPX streaming test (Phase 8E): ignores the
// request body and answers 100KB (102400 'A's) so the mini client must
// stream multiple DATA frames with WINDOW_UPDATE credit (else stalls at
// 64KB). Prints LISTEN, DONE after N exchanges.
import { createSecureServer } from "node:http2";
import { readFileSync } from "node:fs";

const PORT = Number(process.argv[2] ?? 19894);
const DONE_AFTER = Number(process.argv[3] ?? 1);
const CERT = readFileSync("tests/io/tls_test_cert.pem");
const KEY = readFileSync("tests/io/tls_test_key.pem");
const BIG = Buffer.alloc(102400, 65);

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
    stream.respond({ ":status": 200, "content-length": String(BIG.length) });
    stream.end(BIG);
    console.log(`OK BIG path=${headers[":path"]} req=${Buffer.concat(chunks).length} resp=${BIG.length}`);
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
