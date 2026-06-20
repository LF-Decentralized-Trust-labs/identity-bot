import * as ed from "@noble/ed25519";
import {
  IdentityAgentVerifier,
  generateDevSiteIdentity,
  canonicalAssertionBody,
  assertionDigest,
  signCanonical,
  createDevRelayServer,
} from "../../dist/index.js";
import {
  validateDiscoveryConformance,
  verifyIDToken,
  EUDI_ARF_PROFILE_VERSION,
} from "../../dist/oidc/index.js";

/** Minimal discovery builder mirroring Go oidc.BuildDiscovery for conformance test. */
function buildTestDiscovery(issuerBase) {
  return {
    issuer: issuerBase,
    authorization_endpoint: `${issuerBase}/oidc/authorize`,
    response_types_supported: ["id_token", "vp_token", "id_token vp_token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["EdDSA"],
    scopes_supported: ["openid", "profile", "email"],
    claims_supported: ["iss", "sub", "aud", "nonce", "iat", "exp", "name", "email"],
    vp_formats: {
      "vc+sd-jwt": { alg_values_supported: ["EdDSA"], default: true },
      acdc: { alg_values_supported: ["EdDSA"], keri_native: true },
    },
    eudi_arf_profile_version: EUDI_ARF_PROFILE_VERSION,
    siopv2_profile: "siopv2_openid_connect_self_issued_v2",
    openid4vp_profile: "openid4vp_1_0",
    sd_jwt_vc_profile: "sd_jwt_vc_draft_08",
    didwebs_spec_version: "seam-17-v1",
    ia_oidc_adapter_version: "ia-oidc-adapter-v1",
  };
}

async function buildTestIDToken(relayUrl, pairwiseAid, pairwiseSeed, audience, nonce, assertion) {
  const host = new URL(relayUrl).host;
  const did = `did:webs:${host}:${pairwiseAid}`;
  const pub = await ed.getPublicKeyAsync(pairwiseSeed);
  const kid = `${did}#key-1`;
  const header = { alg: "EdDSA", typ: "JWT", kid };
  const claims = {
    iss: did,
    sub: did,
    aud: audience,
    nonce,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 300,
    name: assertion.disclosures.display_name,
    email: assertion.disclosures.email,
    "https://identityagent.org/claims/seam8_assertion_digest": assertion.d,
    "https://identityagent.org/claims/seam8_assertion": assertion,
  };
  const seg =
    Buffer.from(JSON.stringify(header)).toString("base64url") +
    "." +
    Buffer.from(JSON.stringify(claims)).toString("base64url");
  const sig = await ed.signAsync(new TextEncoder().encode(seg), pairwiseSeed);
  return seg + "." + Buffer.from(sig).toString("base64url");
}

async function run() {
  const conformance = validateDiscoveryConformance(
    buildTestDiscovery("http://127.0.0.1:8765/Epairwise"),
  );
  if (!conformance.ok) throw new Error(`conformance: ${conformance.errors.join("; ")}`);
  console.log(`oidc-conformance: EUDI ARF ${conformance.profile} discovery OK`);

  const relay = createDevRelayServer({ port: 0, host: "127.0.0.1" });
  const { url: relayUrl, server: relayServer } = await relay.start();

  const site = await generateDevSiteIdentity(relayUrl);
  relay.registerIdentity(site);

  const verifier = new IdentityAgentVerifier({
    siteIdentity: site,
    devRelayBaseUrl: relayUrl,
  });

  const { bundle } = await verifier.createChallenge({
    audience: "http://127.0.0.1:5000",
    requestedDisclosures: ["display_name", "email"],
    callbackUrl: "http://127.0.0.1:5000/auth/ia/callback",
  });

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

  const idToken = await buildTestIDToken(
    relayUrl,
    pairwiseAid,
    pairwiseSeed,
    bundle.audience,
    bundle.nonce,
    assertion,
  );

  const result = await verifyIDToken(
    idToken,
    { expectedAudience: bundle.audience, expectedNonce: bundle.nonce },
    (a, o) => verifier.verifyAssertion(a, o),
  );
  if (!result.ok) throw new Error(`id_token verify failed: ${result.reason}`);
  if (result.disclosures?.display_name !== "Alice") {
    throw new Error(`disclosures: ${JSON.stringify(result.disclosures)}`);
  }

  console.log("oidc-steel-thread: discovery conformance + id_token → verifyAssertion OK");
  await new Promise((resolve, reject) => relayServer.close((err) => (err ? reject(err) : resolve())));
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});