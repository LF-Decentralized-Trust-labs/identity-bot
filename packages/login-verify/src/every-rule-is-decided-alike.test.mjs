import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { isBrowserKeyThumbprint, readAssertion, thumbprintP256 } from "../dist/canonical.js";
import {
  freshnessWindowSeconds,
  inMemoryConsumedNonces,
  verifyLoginAssertion,
} from "../dist/standalone-verify.js";

// The decisions the Go core makes about a login, run here: how long an
// assertion stays fresh, which binding is checked first and what is said when
// it fails, which browser-key spellings are a thumbprint and how one is made,
// which documents are read at all, and when an assertion is spent. The file
// is produced by the core (TestThePublishedVerifyDecisionsAreTheCores in
// identity-agent-core/login recomputes it), so this package is held to the
// core's answers, reason for reason, not to its own idea of them.
const PKG = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const V = JSON.parse(
  fs.readFileSync(path.join(PKG, "test-vectors", "verify-decisions.json"), "utf8"),
);

let failures = 0;
function check(ok, msg) {
  if (!ok) {
    failures++;
    console.error(`FAIL: ${msg}`);
  }
}

for (const c of V.freshness_windows) {
  const got = freshnessWindowSeconds(c.max_skew_seconds);
  check(got === c.seconds, `window "${c.name}": ${got}, the core ${c.seconds}`);
}

for (const c of V.browser_key_thumbprints) {
  const got = isBrowserKeyThumbprint(c.value);
  check(got === c.go_accepts, `browser key "${c.name}": accepted ${got}, the core ${c.go_accepts}`);
}

for (const c of V.p256_thumbprints) {
  const got = thumbprintP256(c.x, c.y);
  check((got !== null) === c.go_accepts, `P-256 "${c.name}": accepted ${got !== null}, the core ${c.go_accepts}`);
  if (c.go_accepts && got !== null) check(got === c.thumbprint, `P-256 "${c.name}": ${got}, the core ${c.thumbprint}`);
}

// What the verifier says about a document, as the core's decision has it.
async function decide(c, consume) {
  let assertion;
  try {
    assertion = readAssertion(c.assertion_json);
  } catch {
    return { reads: false };
  }
  const result = await verifyLoginAssertion(assertion, {
    expectedNonce: c.expect.nonce,
    expectedAudience: c.expect.audience,
    expectedSiteAid: c.expect.site_aid,
    expectedBrowserKey: c.expect.browser_key,
    maxSkewSeconds: c.max_skew_seconds,
    signingPublicKey: new Uint8Array(Buffer.from(c.public_key_hex, "hex")),
    nowMs: Date.parse(c.now),
    consume,
  });
  return { reads: true, valid: result.valid, reason: result.valid ? undefined : result.reason };
}

const byName = new Map();
for (const c of V.verifications) {
  byName.set(c.name, c);
  const got = await decide(c);
  check(got.reads === c.go_reads, `"${c.name}": read ${got.reads}, the core ${c.go_reads}`);
  if (!c.go_reads || !got.reads) continue;
  check(got.valid === c.go_valid, `"${c.name}": valid ${got.valid} (${got.reason}), the core ${c.go_valid} (${c.go_reason})`);
  if (!c.go_valid && got.valid === false) {
    check(got.reason === c.go_reason, `"${c.name}": refused as "${got.reason}", the core "${c.go_reason}"`);
  }
}

// Spending: a store of its own for each sequence.
for (const seq of V.spending_sequences) {
  const consume = inMemoryConsumedNonces();
  for (const [i, step] of seq.steps.entries()) {
    const got = await decide(byName.get(step.case), consume);
    check(got.valid === step.accepted, `sequence "${seq.name}", step ${i + 1} ("${step.case}"): accepted ${got.valid} (${got.reason}), expected ${step.accepted}`);
    if (!step.accepted && got.valid === false) {
      check(got.reason === step.reason, `sequence "${seq.name}", step ${i + 1}: refused as "${got.reason}", expected "${step.reason}"`);
    }
  }
}

if (failures) {
  console.error(`${failures} disagreement(s) with the core`);
  process.exit(1);
}
console.log(
  `verify decisions: ${V.freshness_windows.length} windows, ${V.browser_key_thumbprints.length} thumbprint spellings, ` +
    `${V.p256_thumbprints.length} P-256 keys, ${V.verifications.length} verifications, ${V.spending_sequences.length} spending sequences`,
);
