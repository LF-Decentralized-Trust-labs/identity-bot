// A third party's website, as its server would be written with this SDK.
//
// It holds no key of its own. It asks its organisation's Identity Agent to
// start a sign-in on the website asset the organisation created, shows the
// person the pointer, and signs somebody in only when the Identity Agent
// confirms it. It also offers a check of a raw assertion against published key
// state, for a site that wants to verify one itself.
//
// Run by the end-to-end test in identity-agent-core/server
// (a_third_party_site_signs_a_person_in_test.go) against a real organisation
// Identity Agent; prints {"url": ...} once it is listening.
//
//   IA_URL=https://ia.example ASSET_ID=the-website node a-third-party-site.mjs
import http from "node:http";
import { startLoginSession, confirmLoginSession } from "../dist/server.js";
import {
  verifyLoginAssertion,
  keyFromIdentityAgent,
  readAssertion,
  inMemoryConsumedNonces,
} from "../../login-verify/dist/index.js";

const IA_URL = process.env.IA_URL;
const ASSET_ID = process.env.ASSET_ID;
const spentSignIns = inMemoryConsumedNonces();
const spentAssertions = inMemoryConsumedNonces();
const secrets = new Map(); // session token -> collector secret, never sent to a browser

function send(res, status, obj) {
  res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(obj));
}
const text = (req) =>
  new Promise((resolve) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => resolve(b));
  });

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  const origin = `http://${req.headers.host}`;
  try {
    if (req.method === "POST" && url.pathname === "/login/start") {
      const s = await startLoginSession({
        agentUrl: IA_URL,
        assetId: ASSET_ID,
        audience: origin,
        requestDisclosures: ["display_name"],
      });
      secrets.set(s.sessionToken, s.collectorSecret);
      return send(res, 200, { session_token: s.sessionToken, pointer_url: s.pointerUrl });
    }
    if (req.method === "GET" && url.pathname === "/login/finish") {
      const token = url.searchParams.get("session") ?? "";
      const secret = secrets.get(token);
      if (!secret) return send(res, 404, { error: "no such sign-in" });
      let out;
      try {
        out = await confirmLoginSession({
          agentUrl: IA_URL,
          assetId: ASSET_ID,
          sessionToken: token,
          collectorSecret: secret,
          consume: spentSignIns,
        });
      } catch (e) {
        return send(res, 409, { error: String(e.message) });
      }
      if (out.state === "pending") return send(res, 202, { state: "pending" });
      if (out.state === "declined") return send(res, 403, { state: "declined" });
      return send(res, 200, {
        state: "signed-in",
        site_session: `site-session-${out.pairwiseAid.slice(0, 12)}`,
        pairwise_aid: out.pairwiseAid,
        disclosures: out.disclosures,
      });
    }
    if (req.method === "POST" && url.pathname === "/login/verify-assertion") {
      const body = JSON.parse(await text(req));
      const assertion = readAssertion(body.assertion);
      const out = await verifyLoginAssertion(assertion, {
        expectedAudience: body.audience,
        expectedNonce: body.nonce,
        expectedSiteAid: body.site_aid,
        resolveKey: keyFromIdentityAgent(IA_URL),
        consume: spentAssertions,
      });
      return send(res, out.valid ? 200 : 401, out);
    }
    send(res, 404, { error: "not found" });
  } catch (e) {
    send(res, 500, { error: String(e.message) });
  }
});
server.listen(0, "127.0.0.1", () => {
  console.log(JSON.stringify({ url: `http://127.0.0.1:${server.address().port}` }));
});
