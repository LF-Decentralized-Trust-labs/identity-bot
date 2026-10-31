import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertionDigest,
  canonicalAssertionBody,
  canonicalChallengeBody,
  decodeMatterRaw,
  decodeVerkeyQb64,
  parseRfc3339,
  readAssertion,
  readChallenge,
  verifyCanonical,
} from "../dist/canonical.js";
import { verifyLoginAssertion } from "../dist/standalone-verify.js";

// Every expectation here was produced by the Go core (its login canonicaliser
// and its key and signature decoders), so this package is held to the core's
// bytes and the core's decisions rather than to its own idea of them. The Go
// test TestThePublishedLoginVectorsAreTheCores recomputes the file from the
// core, so it cannot drift from what the core does.
const PKG = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const V = JSON.parse(
  fs.readFileSync(path.join(PKG, "test-vectors", "core-canonical-and-spellings.json"), "utf8"),
);

let failures = 0;
function check(ok, msg) {
  if (!ok) {
    failures++;
    console.error(`FAIL: ${msg}`);
  }
}

// Read from the text, as the core reads it: a repeated key or a whole number
// written as 1.0 is gone once JSON.parse has run.
function canonical(read, fn, json) {
  try {
    return { reads: true, body: fn(read(json)) };
  } catch {
    return { reads: false };
  }
}

for (const c of V.canonical_assertions) {
  const got = canonical(readAssertion, canonicalAssertionBody, c.json);
  check(got.reads === c.go_reads, `assertion "${c.name}": read ${got.reads}, the core ${c.go_reads}`);
  if (c.go_reads && got.reads) {
    check(got.body === c.canonical_body, `assertion "${c.name}":\n  ts: ${got.body}\n  go: ${c.canonical_body}`);
    const { d, sig, ...rest } = JSON.parse(c.json);
    check(assertionDigest(rest) === c.said, `assertion "${c.name}": digest differs`);
  }
}

for (const c of V.canonical_challenges) {
  const got = canonical(readChallenge, canonicalChallengeBody, c.json);
  check(got.reads === c.go_reads, `challenge "${c.name}": read ${got.reads}, the core ${c.go_reads}`);
  if (c.go_reads && got.reads) {
    check(got.body === c.canonical_body, `challenge "${c.name}":\n  ts: ${got.body}\n  go: ${c.canonical_body}`);
  }
}

function decided(cases, decode, label) {
  for (const c of cases) {
    const raw = decode(c.value);
    const want = c.go_accepts;
    check((raw !== null) === want, `${label} "${c.name}": accepted ${raw !== null}, the core ${want}`);
    if (raw && want) check(Buffer.from(raw).toString("hex") === c.raw_hex, `${label} "${c.name}": wrong bytes`);
  }
}
decided(V.verkey_qb64, decodeVerkeyQb64, "key");
decided(V.non_transferable_aid, (v) => decodeMatterRaw(v, "B", 32), "identifier");

for (const c of V.times) {
  const ms = parseRfc3339(c.value);
  const reads = !Number.isNaN(ms);
  check(reads === c.go_reads, `time "${c.name}" (${c.value}): read ${reads}, the core ${c.go_reads}`);
  if (reads && c.go_reads) check(ms === c.unix_ms, `time "${c.name}": ${ms}, the core ${c.unix_ms}`);
}

for (const c of V.ed25519_signatures) {
  const ok = await verifyCanonical(c.message, c.sig, new Uint8Array(Buffer.from(c.public_key_hex, "hex")));
  check(ok === c.go_accepts, `signature case "${c.name}": verified ${ok}, the core ${c.go_accepts}`);
}

const s = V.signed_assertion;
const pub = new Uint8Array(Buffer.from(s.public_key_hex, "hex"));
const assertion = JSON.parse(s.assertion_json);
check(canonicalAssertionBody(assertion) === s.canonical_body, "signed assertion: canonical body differs");
for (const c of s.signatures) {
  const ok = await verifyCanonical(s.canonical_body, c.sig, pub);
  check(ok === c.go_accepts, `signature "${c.name}": verified ${ok}, the core ${c.go_accepts}`);
  const result = await verifyLoginAssertion(
    { ...assertion, sig: c.sig },
    {
      expectedAudience: assertion.audience,
      expectedNonce: assertion.nonce,
      expectedSiteAid: assertion.site_aid,
      signingPublicKey: pub,
      skipDtCheck: true,
    },
  );
  check(result.valid === c.go_accepts, `assertion signed "${c.name}": valid ${result.valid} (${result.reason})`);
}

// A refused shape is a refusal with a reason, never a throw.
const malformed = await verifyLoginAssertion(
  { ...assertion, disclosures: { a: 1 } },
  {
    expectedAudience: assertion.audience,
    expectedNonce: assertion.nonce,
    expectedSiteAid: assertion.site_aid,
    signingPublicKey: pub,
    skipDtCheck: true,
  },
);
check(!malformed.valid && /malformed/.test(malformed.reason), `a number disclosure: ${malformed.reason}`);

// A time that does not parse is refused, not waved through.
const badDt = await verifyLoginAssertion(
  { ...assertion, dt: "not a time" },
  {
    expectedAudience: assertion.audience,
    expectedNonce: assertion.nonce,
    expectedSiteAid: assertion.site_aid,
    signingPublicKey: pub,
  },
);
check(!badDt.valid && badDt.reason === "bad dt", `an unreadable dt: ${badDt.reason}`);

if (failures) {
  console.error(`${failures} disagreement(s) with the core`);
  process.exit(1);
}
console.log(
  `core agreement: ${V.canonical_assertions.length} assertion and ${V.canonical_challenges.length} challenge bodies, ` +
    `${V.verkey_qb64.length + V.non_transferable_aid.length} key spellings, ${s.signatures.length} signature spellings, ` +
    `${V.times.length} times, ${V.ed25519_signatures.length} Ed25519 cases`,
);
