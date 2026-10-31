import express from "express";
import {
  freshnessWindowSeconds,
  keyFromIdentityAgent,
  parseRfc3339,
  parseStrictJson,
  utf8Text,
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
// The body is kept as sent, so the assertion in it is read from its text as
// the core reads one: a repeated key is gone once JSON.parse has run.
app.use(
  express.json({
    limit: "1mb",
    verify: (req, _res, buf) => {
      (req as unknown as { rawBody?: Buffer }).rawBody = buf;
    },
  }),
);

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
    const raw = (req as unknown as { rawBody?: Buffer }).rawBody;
    let body: Record<string, unknown> | undefined;
    try {
      body = raw ? (parseStrictJson(utf8Text(raw)) as Record<string, unknown>) : undefined;
    } catch (err) {
      return res.status(400).json({ ok: false, reason: `the request cannot be read: ${(err as Error).message}` });
    }
    req.body = body;
    const assertion = req.body?.assertion as LoginAssertion | undefined;
    const expectedAudience = req.body?.expected_audience ?? req.body?.expectedAudience;
    const expectedNonce = req.body?.expected_nonce ?? req.body?.expectedNonce;
    const expectedSiteAid = req.body?.expected_site_aid ?? req.body?.expectedSiteAid;
    const maxSkewSeconds = req.body?.max_skew_seconds ?? req.body?.maxSkewSeconds;
    const referenceNow =
      req.body?.reference_now_rfc3339 ?? req.body?.referenceNowRfc3339;

    if (!assertion || !expectedAudience || !expectedNonce || !expectedSiteAid) {
      return res.status(400).json({
        ok: false,
        reason: "assertion, expected_audience, expected_nonce and expected_site_aid are required",
      });
    }
    // The time check is not something a caller can turn off: a fixed time to
    // check against is reference_now_rfc3339.
    if ((req.body?.skip_dt_check ?? req.body?.skipDtCheck) !== undefined) {
      return res.status(400).json({ ok: false, reason: "skip_dt_check is not taken; give reference_now_rfc3339 to check against a fixed time" });
    }
    if (maxSkewSeconds !== undefined && freshnessWindowSeconds(maxSkewSeconds) === null) {
      return res.status(400).json({ ok: false, reason: "max_skew_seconds must be a whole number of seconds" });
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

    if (referenceNow !== undefined) {
      // A reference time that cannot be read is the caller's mistake, said as
      // such: passed on as NaN it once put every dt inside the window.
      const nowMs = parseRfc3339(referenceNow);
      if (!Number.isFinite(nowMs)) {
        return res.status(400).json({ ok: false, reason: "reference_now_rfc3339 is not an RFC 3339 time" });
      }
      verifyOpts.nowMs = nowMs;
    }

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