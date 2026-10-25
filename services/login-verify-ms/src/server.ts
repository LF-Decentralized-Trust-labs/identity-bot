import express from "express";
import {
  keyFromIdentityAgent,
  parseRfc3339,
  verifyLoginAssertion,
  type LoginAssertion,
} from "@identity-agent/login-verify";
import { runGoldenSelfTest } from "./golden.js";

const PORT = parseInt(process.env.PORT ?? "8091", 10);
const HOST = process.env.HOST ?? "0.0.0.0";
// The organisation Identity Agent asked to check each assertion's key log.
// Without one every assertion is refused: a key the caller supplies is not
// taken, because nothing would tie it to the identifier the assertion names.
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
    const expectedSiteAid = req.body?.expected_site_aid ?? req.body?.expectedSiteAid;
    const maxSkewSeconds = req.body?.max_skew_seconds ?? req.body?.maxSkewSeconds;
    const skipDtCheck = req.body?.skip_dt_check ?? req.body?.skipDtCheck;
    const referenceNow =
      req.body?.reference_now_rfc3339 ?? req.body?.referenceNowRfc3339;

    if (!assertion || !expectedAudience || !expectedNonce || !expectedSiteAid) {
      return res.status(400).json({
        ok: false,
        reason: "assertion, expected_audience, expected_nonce and expected_site_aid are required",
      });
    }
    if (req.body?.signing_verkey_qb64 ?? req.body?.signingVerkeyQb64) {
      return res.status(400).json({
        ok: false,
        reason: "a signing key is not taken from the caller; the key comes from the assertion's key log",
      });
    }

    const verifyOpts: Parameters<typeof verifyLoginAssertion>[1] = {
      expectedAudience,
      expectedNonce,
      expectedSiteAid,
      maxSkewSeconds,
      resolveKey,
    };

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