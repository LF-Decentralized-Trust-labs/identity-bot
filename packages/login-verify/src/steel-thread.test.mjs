import * as ed from "@noble/ed25519";
import {
  IdentityAgentVerifier,
  generateDevSiteIdentity,
  canonicalAssertionBody,
  assertionDigest,
  signCanonical,
  verifyCanonical,
  createDevRelayServer,
  keyFromIdentityAgent,
} from "../dist/index.js";
import { anIdentityAgentStandIn } from "./an-identity-agent-stand-in.mjs";

async function run() {
  const relay = createDevRelayServer({ port: 0, host: "127.0.0.1" });
  const { url: relayUrl, server: relayServer } = await relay.start();
  const ia = await anIdentityAgentStandIn();

  const site = await generateDevSiteIdentity(relayUrl);
  relay.registerIdentity(site);

  const verifier = new IdentityAgentVerifier({
    siteIdentity: site,
    devRelayBaseUrl: relayUrl,
    resolveKey: keyFromIdentityAgent(ia.url),
  });

  const { session_token, bundle } = await verifier.createChallenge({
    audience: "http://127.0.0.1:5000",
    requestedDisclosures: ["display_name", "email"],
    callbackUrl: "http://127.0.0.1:5000/auth/ia/callback",
  });

  // Simulate IA: create pairwise AID and sign assertion
  const pairwiseSeed = ed.utils.randomPrivateKey();
  const pairwisePub = await ed.getPublicKeyAsync(pairwiseSeed);
  const pairwiseAid = `E${Buffer.from(pairwisePub).toString("base64url").slice(0, 43)}`;
  relay.registerIdentity({
    aid: pairwiseAid,
    publicKey: pairwisePub,
    privateKey: pairwiseSeed,
    oobiUrl: `${relayUrl}/oobi/${pairwiseAid}`,
  });

  const assertion = {
    v: "IALOGIN10JSON",
    t: "login-assertion",
    i: pairwiseAid,
    relationship_aid_oobi: `${relayUrl}/oobi/${pairwiseAid}`,
    audience: bundle.audience,
    nonce: bundle.nonce,
    dt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    disclosures: { display_name: "Alice", email: "alice@example.com" },
    presented_acdcs: [],
    p_kel: "alices-signed-key-log",
    site_aid: bundle.site_aid,
  };
  ia.knows(pairwiseAid, assertion.p_kel, pairwisePub);
  assertion.d = assertionDigest(assertion);
  const body = canonicalAssertionBody(assertion);
  assertion.sig = await signCanonical(body, pairwiseSeed);

  const result = await verifier.verifyAssertion(assertion, {
    expectedAudience: bundle.audience,
    expectedNonce: bundle.nonce,
    expectedSiteAid: site.aid,
  });
  if (!result.valid) throw new Error(`verify failed: ${result.reason}`);

  // The same person's genuine assertion, approved for another site's challenge
  // that copied this one's audience and nonce, does not sign in here.
  const relayed = { ...assertion, site_aid: "EAnotherSiteThatCopiedTheChallenge" };
  delete relayed.sig;
  relayed.d = assertionDigest(relayed);
  relayed.sig = await signCanonical(canonicalAssertionBody(relayed), pairwiseSeed);
  const refused = await verifier.verifyAssertion(relayed, {
    expectedAudience: bundle.audience,
    expectedNonce: bundle.nonce,
    expectedSiteAid: site.aid,
  });
  if (refused.valid || !refused.reason?.startsWith("site mismatch")) {
    throw new Error(`an assertion approved for another site's challenge verified here: ${refused.reason}`);
  }

  const callback = await verifier.handleCallback(assertion, session_token, (aid) => `tok-${aid.slice(0, 8)}`);
  if (!callback.ok) throw new Error(`callback failed: ${callback.reason}`);

  const state = verifier.getSessionState(session_token);
  if (state?.state !== "verified") throw new Error(`expected verified, got ${state?.state}`);

  // The key was established from the log the assertion carried.
  if (!ia.asked.some((q) => q.aid === pairwiseAid && q.key_log === assertion.p_kel)) {
    throw new Error("the verifier did not ask the Identity Agent about the assertion's key log");
  }

  console.log("steel-thread: challenge → assertion → verify → session verified");
  await ia.close();
  await new Promise((resolve, reject) => relayServer.close((err) => (err ? reject(err) : resolve())));
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});