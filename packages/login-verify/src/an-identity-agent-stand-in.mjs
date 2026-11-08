import http from "node:http";
import { randomBytes } from "node:crypto";
import * as ed from "@noble/ed25519";
import { assertionDigest, canonicalAssertionBody, signCanonical } from "../dist/index.js";

/**
 * Stands in for an Identity Agent's key check (POST /public/login/key) in
 * tests that have no Identity Agent running, and for the sign-in widget routes
 * a web page with only the login SDK uses (/api/login/session/...), which it
 * answers the way the core does: the audience is the asking page's Origin, the
 * result is handed once to the holder of the collector secret, and `answer`
 * plays the person's Identity Agent posting a signed assertion.
 *
 * Its key check answers with a key only for an (identifier, key log) pair it
 * was told about, the way the real check answers only for a log that derives
 * the identifier. The real check is tested in the
 * Identity Agent itself; this tests the wire between the two.
 */
export async function anIdentityAgentStandIn() {
  const known = new Map();
  const asked = [];
  const siteAid = "ETheWebsiteAssetTheOwnersAgentHolds0000000";
  const sessions = new Map();
  const reply = (res, code, obj) =>
    res
      .writeHead(code, { "content-type": "application/json", "access-control-allow-origin": "*" })
      .end(JSON.stringify(obj));
  const widget = (req, res, body) => {
    const m = /^\/api\/login\/session\/([^/]+)(?:\/([^/]+))?$/.exec(req.url);
    if (!m) return false;
    const origin = req.headers.origin ?? "";
    if (req.method === "OPTIONS") return res.writeHead(204, { "access-control-allow-origin": "*" }).end(), true;
    if (req.method === "POST" && !m[2]) {
      const asked = JSON.parse(body || "{}");
      if (origin === "null") return reply(res, 400, { error: "this page has no origin to sign in to" }), true;
      if (origin && asked.audience && asked.audience !== origin) return reply(res, 400, { error: "a page signs in to its own origin only" }), true;
      const token = randomBytes(16).toString("hex");
      const secret = randomBytes(32).toString("base64url");
      sessions.set(token, { audience: origin || asked.audience || "", nonce: randomBytes(32).toString("base64url"), secret, status: "pending" });
      return reply(res, 200, { session_token: token, relay_or_qr_url: `http://127.0.0.1:${port()}/i/${token}`, collector_secret: secret }), true;
    }
    if (req.method === "GET" && m[2]) {
      const sn = sessions.get(m[2]);
      if (!sn) return reply(res, 200, { state: "connecting" }), true;
      const held = req.headers["x-collector-secret"] === sn.secret;
      if (sn.status === "pending") return reply(res, 200, { state: "connecting" }), true;
      if (sn.status === "denied") return reply(res, 200, { state: "declined" }), true;
      if (!held || sn.released) return reply(res, 200, { state: "verified", identity_withheld: true }), true;
      sn.released = true;
      return reply(res, 200, {
        state: "verified", app_session_token: sn.pairwise, disclosures: sn.disclosures,
        assertion: sn.assertion, nonce: sn.nonce, site_aid: siteAid,
      }), true;
    }
    return false;
  };
  let port = () => 0;
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      if (widget(req, res, body)) return;
      if (req.method === "OPTIONS" && req.url === "/public/login/key") {
        res.writeHead(204, { "access-control-allow-origin": "*", "access-control-allow-headers": "Content-Type" }).end();
        return;
      }
      if (req.method !== "POST" || req.url !== "/public/login/key") {
        res.writeHead(404).end();
        return;
      }
      const { aid, key_log } = JSON.parse(body || "{}");
      asked.push({ aid, key_log });
      const pub = known.get(`${aid}|${key_log}`);
      res.setHeader("content-type", "application/json");
      res.setHeader("access-control-allow-origin", "*");
      if (!pub) {
        res.writeHead(422).end(JSON.stringify({ error: `the key log of ${aid} establishes no key` }));
        return;
      }
      res.end(JSON.stringify({ aid, public_key_b64: Buffer.from(pub).toString("base64url") }));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port: listening } = server.address();
  port = () => listening;
  return {
    url: `http://127.0.0.1:${listening}`,
    siteAid,
    asked,
    sessions,
    /** The person's Identity Agent answers a started sign-in with a signed
     *  assertion for `aid` (its key log `keyLog`, its key `seed`); the Identity
     *  Agent here has checked nothing else. Returns the assertion text. */
    async answer(token, { aid, seed, keyLog, disclosures = { display_name: "Alice" }, dt }) {
      const sn = sessions.get(token);
      const a = {
        v: "IALOGIN10JSON", t: "login-assertion", i: aid,
        relationship_aid_oobi: `http://127.0.0.1:${listening}/oobi/${aid}`,
        audience: sn.audience, nonce: sn.nonce,
        dt: dt ?? new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
        disclosures, presented_acdcs: [], site_aid: siteAid, p_kel: keyLog,
      };
      a.d = assertionDigest(a);
      a.sig = await signCanonical(canonicalAssertionBody(a), seed);
      Object.assign(sn, { status: "complete", pairwise: aid, disclosures, assertion: JSON.stringify(a) });
      return sn.assertion;
    },
    /** A person whose key log this Identity Agent will say establishes their key
     *  (`known`), or, with `established: false`, one whose log it will not. */
    async aPerson(name, { established = true } = {}) {
      const seed = ed.utils.randomPrivateKey();
      const aid = `E${name}`.padEnd(44, "0");
      const keyLog = `${name}s-signed-key-log`;
      if (established) known.set(`${aid}|${keyLog}`, await ed.getPublicKeyAsync(seed));
      return { aid, keyLog, seed };
    },
    decline(token) {
      sessions.get(token).status = "denied";
    },
    knows(aid, keyLog, publicKey) {
      known.set(`${aid}|${keyLog}`, publicKey);
    },
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
