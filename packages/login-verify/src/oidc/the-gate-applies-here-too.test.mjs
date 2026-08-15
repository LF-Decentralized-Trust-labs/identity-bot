import * as ed from "@noble/ed25519";
import { verifyIDToken } from "../../dist/oidc/idtoken.js";

// The OIDC path must be able to refuse somebody who is who they say they are.
//
// This is the path a third party integrates without reading the source. If a
// verifying id_token were admitted without asking whether the person is
// allowed, an organisation's policy would apply to exactly the integrations we
// wrote ourselves and to none of the ones that matter.
//
// The token below is REALLY signed and the key REALLY resolved, because an
// earlier version of this test stubbed both, failed signature verification
// before ever reaching the gate, and reported the refusal as a pass.

async function run() {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  const aid = "E" + Buffer.from(pub).toString("base64url").slice(0, 43);
  const iss = `did:webs:relay.test:${aid}`;

  const assertion = {
    v: "IALOGIN10JSON", t: "login-assertion", i: aid,
    audience: "https://portal.example", nonce: "a-nonce", sig: "unused-here",
  };
  const header = { alg: "EdDSA", kid: `${iss}#0`, typ: "JWT" };
  const payload = { iss, sub: aid, aud: "https://portal.example",
                    nonce: "a-nonce",
                    ["https://identityagent.org/claims/seam8_assertion"]: assertion };
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const signing = `${b64(header)}.${b64(payload)}`;
  const sig = await ed.signAsync(new TextEncoder().encode(signing), priv);
  const token = `${signing}.${Buffer.from(sig).toString("base64url")}`;

  // The relay that publishes this identifier's key.
  const fetchFn = async () => ({
    ok: true,
    json: async () => ({
      verificationMethod: [{ publicKeyJwk: { x: Buffer.from(pub).toString("base64url") } }],
    }),
  });

  const opts = { expectedAudience: "https://portal.example", expectedNonce: "a-nonce", fetchFn };
  const substrateOk = async () => ({ valid: true });

  // Guard: if the signature path breaks, everything below would pass vacuously.
  const baseline = await verifyIDToken(token, opts, substrateOk);
  if (!baseline.ok) throw new Error(`the token itself does not verify: ${baseline.reason}`);

  const refused = await verifyIDToken(token, opts, substrateOk,
    async () => ({ allowed: false, reason: "not an active employee" }));
  if (refused.ok) throw new Error("a refused person was admitted through OIDC");
  if (String(refused.reason).includes("employee")) {
    throw new Error(`the refusal leaked the gate reason: ${refused.reason}`);
  }

  const allowed = await verifyIDToken(token, opts, substrateOk, async () => ({ allowed: true }));
  if (!allowed.ok) throw new Error(`an allowed person was refused: ${allowed.reason}`);
  if (allowed.authorized !== true) throw new Error("an applied policy was not reported");

  if (baseline.authorized !== undefined) {
    throw new Error("no policy supplied should report undefined, not authorised");
  }

  console.log("oidc gate: refuses, admits, and says when no policy was applied");
}
run().catch((e) => { console.error(String(e.message || e)); process.exit(1); });
