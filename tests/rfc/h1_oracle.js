// H1 oracle: plain HTTP/1.1 echo for RFC 9110/9112 conformance.
// Builtins only (node:http), so the same file runs under node and
// bun. Two modes:
//   node h1_oracle.js server [port] [n]  — echo server, DONE n/n
//   node h1_oracle.js client <port>       — one-shot check vs any
//     server (Bend or this oracle), DONE 3/3
// Routes: POST /echo (byte echo), GET /chunk (chunked "Wikipedia"),
// GET /close (Connection: close), anything else 404.
import http from "node:http";

const MODE = process.argv[2] ?? "server";
const PORT = Number(process.argv[3] ?? 19881);
const DONE_AFTER = Number(process.argv[4] ?? 1);

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
function counted(server, label, len) {
  console.log(`OK ${label} len=${len}`);
  exchanges += 1;
  if (exchanges >= DONE_AFTER) {
    console.log(`DONE ${exchanges}/${DONE_AFTER}`);
    server.close();
  }
}

/** Starts the echo server. */
function serve() {
  const server = http.createServer((req, res) => {
    if (req.url === "/chunk" && req.method === "GET") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.write("Wiki");
      res.end("pedia");
      counted(server, "CHUNK", 9);
    } else if (req.url === "/close") {
      res.writeHead(200, {
        "content-length": "2",
        connection: "close",
      });
      res.end("hi");
      counted(server, "CLOSE", 2);
    } else if (req.url === "/echo") {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        const body = Buffer.concat(chunks);
        res.writeHead(200, {
          "content-type": "application/octet-stream",
          "content-length": String(body.length),
        });
        res.end(body);
        counted(server, "ECHO", body.length);
      });
    } else {
      res.writeHead(404, { "content-length": "0" });
      res.end();
      counted(server, "MISS", 0);
    }
  });
  server.listen(PORT, "127.0.0.1", () => {
    console.log(`LISTEN ${PORT}`);
  });
}

/**
 * Reads one response body fully.
 *
 * @param res {import("node:http").IncomingMessage} - The response.
 */
function readBody(res) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    res.on("data", (c) => chunks.push(c));
    res.on("end", () => resolve(Buffer.concat(chunks)));
    res.on("error", reject);
  });
}

/**
 * One request over the shared agent (keep-alive reuse is the point).
 *
 * @param agent {import("node:http").Agent} - Shared agent.
 * @param options {object} - Request options.
 * @param body {string} - Body to send.
 */
function once(agent, options, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ ...options, agent }, (res) => {
      readBody(res).then((buf) => resolve({ res, buf }));
    });
    req.on("error", reject);
    req.end(body);
  });
}

/** Runs the 3-step client script against PORT. */
async function runClient() {
  const agent = new http.Agent({ keepAlive: true });
  const base = { host: "127.0.0.1", port: PORT };
  let r = await once(agent, { ...base, path: "/echo", method: "POST" }, "hello");
  check(r.res.statusCode === 200 && r.buf.toString() === "hello", "ECHO");
  r = await once(agent, { ...base, path: "/chunk", method: "GET" }, "");
  check(r.res.statusCode === 200 && r.buf.toString() === "Wikipedia", "CHUNKED");
  r = await once(agent, { ...base, path: "/echo", method: "POST" }, "again");
  check(r.res.statusCode === 200 && r.buf.toString() === "again", "REUSE");
  console.log(`DONE ${score}/3`);
  agent.destroy();
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
