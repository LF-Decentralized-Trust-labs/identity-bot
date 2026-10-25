import express from "express";
import {
  decodeVerkeyQb64,
  keyFromIdentityAgent,
  parseRfc3339,
  verifyLoginAssertion,
  type LoginAssertion,
} from "@identity-agent/login-verify";
import { runGoldenSelfTest } from "./golden.js";

const PORT = parseInt(process.env.PORT ?? "8091", 10);
const HOST = process.env.HOST ?? "0.0.0.0";
// The Identity Agent asked to check each assertion's key log. Without one, an
// assertion verifies only against a signing_verkey_qb64 the caller supplies.
const IDENTITY_AGENT_URL = process.env.IDENTITY_AGENT_URL;
const resolveKey = IDENTITY_AGENT_URL ? keyFromIdentityAgent(IDENTITY_AGENT_URL) : undefined;

let goldenOk = false;
let goldenReason = "not run";

const app = express();
app.use(express.json({ limit: "1mb" }));

app.get("/health", (_req, res) => {
  res.json({
    status: goldenOk ? "active" : "degraded",
    service: "login-verify-ms",
    version: "0.1.0",
    golden_vector_ok: goldenOk,
    ...(goldenOk ? {} : { golden_vector_error: goldenReason }),
  });
});

app.post("/verify", async (req, res) => {
  try {
    const assertion = req.body?.assertion as LoginAssertion | undefined;
    const expectedAudience = req.body?.expected_audience ?? req.body?.expectedAudience;
    const expectedNonce = req.body?.expected_nonce ?? req.body?.expectedNonce;
    const maxSkewSeconds = req.body?.max_skew_seconds ?? req.body?.maxSkewSeconds;
    const signingVerkeyQb64 =
      req.body?.signing_verkey_qb64 ?? req.body?.signingVerkeyQb64;
    const skipDtCheck = req.body?.skip_dt_check ?? req.body?.skipDtCheck;
    const referenceNow =
      req.body?.reference_now_rfc3339 ?? req.body?.referenceNowRfc3339;

    if (!assertion || !expectedAudience || !expectedNonce) {
      return res.status(400).json({
        ok: false,
        reason: "assertion, expected_audience, and expected_nonce are required",
      });
    }

    const verifyOpts: Parameters<typeof verifyLoginAssertion>[1] = {
      expectedAudience,
      expectedNonce,
      maxSkewSeconds,
      resolveKey,
    };

    if (signingVerkeyQb64) {
      const pub = decodeVerkeyQb64(signingVerkeyQb64);
      if (!pub) {
        return res.status(400).json({ ok: false, reason: "invalid signing_verkey_qb64" });
      }
      verifyOpts.signingPublicKey = pub;
    }
    if (skipDtCheck) verifyOpts.skipDtCheck = true;
    if (referenceNow) verifyOpts.nowMs = parseRfc3339(referenceNow);

    const result = await verifyLoginAssertion(assertion, verifyOpts);

    if (!result.valid) {
      return res.status(401).json(result);
    }

    res.json({
      ok: true,
      i: result.pairwiseAID,
      disclosures: result.disclosures,
      presented_acdcs: result.presentedAcdcs,
      custom_data: result.customData,
      audience: result.audience,
      nonce: result.nonce,
      dt: result.dt,
    });
  } catch (err) {
    res.status(500).json({ ok: false, reason: (err as Error).message });
  }
});

async function main() {
  const golden = await runGoldenSelfTest();
  goldenOk = golden.ok;
  goldenReason = golden.reason ?? "";
  if (!goldenOk) {
    console.error(`[login-verify-ms] GOLDEN VECTOR SELF-TEST FAILED: ${goldenReason}`);
  } else {
    console.log("[login-verify-ms] golden vector self-test passed");
  }

  app.listen(PORT, HOST, () => {
    console.log(`[login-verify-ms] listening on http://${HOST}:${PORT}`);
    console.log("[login-verify-ms] POST /verify  GET /health");
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});