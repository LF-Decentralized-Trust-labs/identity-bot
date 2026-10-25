import * as ed from "@noble/ed25519";
import http from "node:http";
import {
  IdentityAgentVerifier,
  generateDevSiteIdentity,
  canonicalAssertionBody,
  assertionDigest,
  signCanonical,
  verifyLoginAssertion,
  keyFromIdentityAgent,
  NO_KEY_RESOLVER,
} from "../dist/index.js";
import { verifyIDToken } from "../dist/oidc/idtoken.js";
import { anIdentityAgentStandIn } from "./an-identity-agent-stand-in.mjs";

// A key is tied to an identifier only by the identifier's own key log. These
// verifiers used to read a key from a did.json at the address the assertion
// named, which the assertion's author also chose — so anybody could sign in as
// any identifier. Now a verifier with no way to check a key log refuses, and
// one that has a way asks it about the log the assertion carries.

let lureUrl = "";
const SITE = "EThePortalWhoseChallengeThisAnswers00000000";

async function anAssertion(aid, seed, keyLog) {
  const a = {
    v: "IALOGIN10JSON", t: "login-assertion", i: aid,
    relationship_aid_oobi: `${lureUrl}/oobi/${aid}`,
    audience: "https://portal.example", nonce: "a-nonce",
    dt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    disclosures: {}, presented_acdcs: [], site_aid: SITE,
  };
  if (keyLog !== undefined) a.p_kel = keyLog;
  a.d = assertionDigest(a);
  a.sig = await signCanonical(canonicalAssertionBody(a), seed);
  return a;
}

async function run() {
  const seed = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(seed);
  const aid = "EAliceTheEmployee000000000000000000000000000";
  const opts = { expectedAudience: "https://portal.example", expectedNonce: "a-nonce", expectedSiteAid: SITE };

  // Anything at the address the assertion names would be a key the attacker
  // chose. Nothing may be read from it.
  let fetched = 0;
  const lure = http.createServer((req, res) => { fetched++; res.writeHead(404).end(); });
  await new Promise((r) => lure.listen(0, "127.0.0.1", r));
  lureUrl = `http://127.0.0.1:${lure.address().port}`;

  const a = await anAssertion(aid, seed, "alices-signed-key-log");

  // 1. No way to check a key log: refused, on every path.
  const site = await generateDevSiteIdentity("http://127.0.0.1:1");
  const bare = new IdentityAgentVerifier({ siteIdentity: site });
  for (const [name, result] of [
    ["class", await bare.verifyAssertion(a, opts)],
    ["standalone", await verifyLoginAssertion(a, opts)],
  ]) {
    if (result.valid) throw new Error(`${name}: verified with no way to check the key log`);
    if (result.reason !== NO_KEY_RESOLVER) throw new Error(`${name}: wrong reason: ${result.reason}`);
  }
  const header = Buffer.from(JSON.stringify({ alg: "EdDSA", kid: `did:webs:x:${aid}#0` })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ iss: `did:webs:x:${aid}`, aud: opts.expectedAudience,
    nonce: opts.expectedNonce, ["https://identityagent.org/claims/seam8_assertion"]: a })).toString("base64url");
  const jwtSig = await ed.signAsync(new TextEncoder().encode(`${header}.${payload}`), seed);
  const token = `${header}.${payload}.${Buffer.from(jwtSig).toString("base64url")}`;
  const tok = await verifyIDToken(token, opts, async () => ({ valid: true }));
  if (tok.ok || tok.reason !== NO_KEY_RESOLVER) {
    throw new Error(`id token: verified with no way to check the key log (${tok.reason})`);
  }

  // 2. With an Identity Agent to ask: the assertion's own log is what is asked about.
  const ia = await anIdentityAgentStandIn();
  ia.knows(aid, "alices-signed-key-log", pub);
  const resolveKey = keyFromIdentityAgent(ia.url);
  const ok = await verifyLoginAssertion(a, { ...opts, resolveKey });
  if (!ok.valid) throw new Error(`a genuine assertion was refused: ${ok.reason}`);
  const last = ia.asked[ia.asked.length - 1];
  if (last.aid !== aid || last.key_log !== "alices-signed-key-log") {
    throw new Error(`the Identity Agent was asked the wrong thing: ${JSON.stringify(last)}`);
  }

  // 3. A log the Identity Agent says establishes nothing: refused, with its reason.
  const mallory = await anAssertion(aid, ed.utils.randomPrivateKey(), "mallorys-own-key-log");
  const no = await verifyLoginAssertion(mallory, { ...opts, resolveKey });
  if (no.valid) throw new Error("an assertion whose log establishes no key was accepted");
  if (!String(no.reason).includes("establishes no key")) throw new Error(`wrong reason: ${no.reason}`);

  // 4. No log at all: refused without asking anybody.
  const before = ia.asked.length;
  const none = await verifyLoginAssertion(await anAssertion(aid, seed, undefined), { ...opts, resolveKey });
  if (none.valid) throw new Error("an assertion with no key log was accepted");
  if (ia.asked.length !== before) throw new Error("an assertion with no key log was still sent to be checked");

  // 5. An Identity Agent asked over plain HTTP elsewhere could be answered by
  // anybody on the path, so it is not asked at all.
  let refusedPlainHttp = false;
  try { keyFromIdentityAgent("http://identity-agent.example"); } catch { refusedPlainHttp = true; }
  if (!refusedPlainHttp) throw new Error("an Identity Agent was to be asked for keys over plain HTTP");

  if (fetched !== 0) throw new Error(`a key was read from the address an assertion named (${fetched} requests)`);

  await ia.close();
  await new Promise((r) => lure.close(r));
  console.log("key logs: no resolver refuses; the assertion's own log is checked; nothing else is read");
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
