import http from "node:http";

/**
 * Stands in for an Identity Agent's key check (POST /public/login/key) in
 * tests that have no Identity Agent running. It answers with a key only for an
 * (identifier, key log) pair it was told about, the way the real check answers
 * only for a log that derives the identifier. The real check is tested in the
 * Identity Agent itself; this tests the wire between the two.
 */
export async function anIdentityAgentStandIn() {
  const known = new Map();
  const asked = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      if (req.method !== "POST" || req.url !== "/public/login/key") {
        res.writeHead(404).end();
        return;
      }
      const { aid, key_log } = JSON.parse(body || "{}");
      asked.push({ aid, key_log });
      const pub = known.get(`${aid}|${key_log}`);
      res.setHeader("content-type", "application/json");
      if (!pub) {
        res.writeHead(422).end(JSON.stringify({ error: `the key log of ${aid} establishes no key` }));
        return;
      }
      res.end(JSON.stringify({ aid, public_key_b64: Buffer.from(pub).toString("base64url") }));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    asked,
    knows(aid, keyLog, publicKey) {
      known.set(`${aid}|${keyLog}`, publicKey);
    },
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
