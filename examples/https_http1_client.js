import { request as httpsRequest } from "node:https";

const port = Number(process.argv[2] ?? 19895);
const body = "hello";
const req = httpsRequest({
  hostname: "127.0.0.1",
  port,
  path: "/echo",
  method: "POST",
  rejectUnauthorized: false,
  headers: { "content-length": String(body.length) },
}, (res) => {
  const chunks = [];
  res.on("data", (chunk) => chunks.push(chunk));
  res.on("end", () => {
    const text = Buffer.concat(chunks).toString();
    if (res.statusCode !== 200 || text !== body) {
      console.log(`FAIL status=${res.statusCode} body=${JSON.stringify(text)}`);
      process.exitCode = 1;
      return;
    }
    console.log("DONE 3/3");
  });
});
req.on("error", (error) => {
  console.log(`FAIL ${error.message}`);
  process.exitCode = 1;
});
req.end(body);
