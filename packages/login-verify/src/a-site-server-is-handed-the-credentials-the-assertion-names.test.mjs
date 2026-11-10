// ADR-071. A site whose server asks for credentials (requestCredentials) is
// handed, through onVerified, the credentials posted beside the assertion that
// the assertion's signature names and whose bodies have the SAID it signed.
// The posted ones are not signed, so one the assertion does not name, or whose
// body was changed, never reaches the site.
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import * as ed from "@noble/ed25519";
import express from "express";
import {
  IdentityAgentVerifier, assertionDigest, canonicalAssertionBody, generateDevSiteIdentity,
  mountIdentityAgentLoginRoutes, nonTransferableAidQb64, signCanonical,
} from "../dist/index.js";

const PKG = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const V = JSON.parse(fs.readFileSync(path.join(PKG, "test-vectors", "core-canonical-and-spellings.json"), "utf8"));
const both = JSON.parse(V.sign_in_posts.find((c) => c.name === "both credentials posted and named").post);
const [first, second] = both.credentials;
const forged = JSON.parse(V.sign_in_posts.find((c) => c.name === "a body whose attribute block was changed after the digest was signed").post)
  .credentials[0];

const site = await generateDevSiteIdentity("http://relay.example");
const personSeed = ed.utils.randomPrivateKey();
const personPub = await ed.getPublicKeyAsync(personSeed);
const personAid = nonTransferableAidQb64(personPub);

async function signIn(presented, credentials) {
  let handed = null;
  const verifier = new IdentityAgentVerifier({ siteIdentity: site, resolveKey: async () => personPub });
  const app = express();
  mountIdentityAgentLoginRoutes(app, verifier, { onVerified: (r) => { handed = r; } });
  const server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const started = await fetch(`${base}/auth/ia/session`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ requestCredentials: [{ schema_said: first.schema_said, required: true }] }),
    });
    const { session_token } = await started.json();
    const challenge = await (await fetch(`${base}/i/${session_token}`)).json();
    const a = {
      v: "IALOGIN10JSON", t: "login-assertion", i: personAid, relationship_aid_oobi: "o",
      audience: challenge.audience, nonce: challenge.nonce,
      dt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"), disclosures: {}, presented_acdcs: presented,
      p_kel: "kel", site_aid: site.aid,
    };
    a.d = assertionDigest(a);
    a.sig = await signCanonical(canonicalAssertionBody(a), personSeed);
    const res = await fetch(`${base}/auth/ia/callback?session=${session_token}`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ assertion: a, credentials }),
    });
    assert.equal(res.status, 200, await res.text());
    return handed;
  } finally {
    server.close();
  }
}

// Named and posted: the site's server is handed it, and only it.
let got = await signIn([first.said], [first, second]);
assert.deepEqual(got.credentials.map((c) => c.said), [first.said]);
assert.deepEqual(got.credentials[0], first);

// A body changed after the digest was signed is not handed over.
got = await signIn([first.said], [forged]);
assert.deepEqual(got.credentials, []);

// A sign-in that presented nothing hands over nothing.
got = await signIn([], [first]);
assert.deepEqual(got.credentials, []);
console.log("a site's server is handed the credentials the assertion names: ok");
