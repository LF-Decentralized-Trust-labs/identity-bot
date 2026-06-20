import * as ed from "@noble/ed25519";
import {
  IdentityAgentVerifier,
  generateDevSiteIdentity,
  canonicalAssertionBody,
  assertionDigest,
  signCanonical,
  verifyCanonical,
  createDevRelayServer,
} from "../dist/index.js";

async function run() {
  const relay = createDevRelayServer({ port: 0, host: "127.0.0.1" });
  const { url: relayUrl, server: relayServer } = await relay.start();

  const site = await generateDevSiteIdentity(relayUrl);
  relay.registerIdentity(site);

  const verifier = new IdentityAgentVerifier({
    siteIdentity: site,
    devRelayBaseUrl: relayUrl,
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
  };
  assertion.d = assertionDigest(assertion);
  const body = canonicalAssertionBody(assertion);
  assertion.sig = await signCanonical(body, pairwiseSeed);

  const result = await verifier.verifyAssertion(assertion, {
    expectedAudience: bundle.audience,
    expectedNonce: bundle.nonce,
  });
  if (!result.ok) throw new Error(`verify failed: ${result.reason}`);

  const callback = await verifier.handleCallback(assertion, session_token, (aid) => `tok-${aid.slice(0, 8)}`);
  if (!callback.ok) throw new Error(`callback failed: ${callback.reason}`);

  const state = verifier.getSessionState(session_token);
  if (state?.state !== "verified") throw new Error(`expected verified, got ${state?.state}`);

  console.log("steel-thread: challenge → assertion → verify → session verified");
  await new Promise((resolve, reject) => relayServer.close((err) => (err ? reject(err) : resolve())));
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});