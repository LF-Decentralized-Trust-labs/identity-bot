#!/usr/bin/env node
/** T-140 — regenerate golden_vectors.json from frozen M29 seed. */
import * as fs from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import * as ed from "@noble/ed25519";
import {
  M29_GOLDEN_ASSERTION_INPUT,
  M29_GOLDEN_SIGNING_SEED,
} from "../dist/golden-seed.js";
import {
  assertionDigest,
  canonicalAssertionBody,
  ed25519VerkeyQb64,
  signCanonical,
} from "../dist/canonical.js";

const PKG = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = path.join(PKG, "golden_vectors.json");

async function main() {
  const pub = await ed.getPublicKeyAsync(M29_GOLDEN_SIGNING_SEED);
  const base = { ...M29_GOLDEN_ASSERTION_INPUT };
  const d = assertionDigest(base);
  const assertion = { ...base, d };
  const canonicalBody = canonicalAssertionBody(assertion);
  const canonicalBytes = Buffer.from(canonicalBody, "utf8");
  const sig = await signCanonical(canonicalBody, M29_GOLDEN_SIGNING_SEED);

  const golden = {
    login_assertion: {
      description:
        "M29 SEAM-8 OQ-1 frozen — deterministic login assertion (seed 0x29..0x48)",
      seam: "SEAM-8",
      oq: "OQ-1",
      version: "IALOGIN10JSON",
      seed_hex: Buffer.from(M29_GOLDEN_SIGNING_SEED).toString("hex"),
      field_order:
        "v,t,d,i,relationship_aid_oobi,audience,nonce,dt,disclosures,presented_acdcs",
      canonical_rules: {
        json: "compact, no insignificant whitespace, no trailing newline",
        strings: "NFC-normalized UTF-8",
        timestamps: "RFC 3339 UTC trailing Z, integer seconds",
        nonce: "base64url no-pad",
        said_algorithm: "Blake3-256 Matter qb64 code E over body minus d and sig",
        signature:
          "Ed25519 over UTF-8 canonical body including d, excluding sig; CESR 0B qb64",
      },
      pairwise_aid: base.i,
      signing_verkey_qb64: ed25519VerkeyQb64(pub),
      relationship_aid_oobi: base.relationship_aid_oobi,
      audience: base.audience,
      nonce: base.nonce,
      dt: base.dt,
      disclosures: base.disclosures,
      presented_acdcs: base.presented_acdcs,
      said: d,
      sig,
      canonical_body: canonicalBody,
      canonical_body_len: canonicalBytes.length,
      canonical_body_sha256_hex: createHash("sha256").update(canonicalBytes).digest("hex"),
      assertion: { ...assertion, sig },
      expected_verify: {
        audience: base.audience,
        nonce: base.nonce,
        max_skew_seconds: 300,
        reference_now_rfc3339: "2026-06-17T12:00:00Z",
      },
      negative_vectors: {
        corrupt_sig_last_char: sig.slice(0, -1) + (sig.endsWith("A") ? "B" : "A"),
        wrong_nonce: "m29GoldenNonce0123456789ABCDEFG0",
        wrong_audience: "https://evil.example.com",
      },
    },
  };

  fs.writeFileSync(OUT, JSON.stringify(golden, null, 2) + "\n");
  console.log(`Pinned ${OUT}`);
  console.log(`  said: ${d}`);
  console.log(`  canonical_body_len: ${canonicalBytes.length}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});