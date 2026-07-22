import { blake3 } from "@noble/hashes/blake3";
import * as ed from "@noble/ed25519";
import type { LoginAssertion, LoginChallenge } from "./types.js";

/** keri 1.1.17 Matter fixed-size qb64 (matches the core hybrid PQC CESR encoding). */
export function matterFixedQb64(code: string, raw: Uint8Array): string {
  const ps = (3 - (raw.length % 3)) % 3;
  const padded = new Uint8Array(ps + raw.length);
  padded.set(raw, ps);
  const b64 = Buffer.from(padded).toString("base64url");
  return code + b64.slice(code.length % 4);
}

export function blake3Qb64(data: Uint8Array): string {
  return matterFixedQb64("E", blake3(data));
}

export function ed25519SigQb64(sig: Uint8Array): string {
  return matterFixedQb64("0B", sig);
}

export function ed25519VerkeyQb64(pub: Uint8Array): string {
  return matterFixedQb64("D", pub);
}

export function decodeVerkeyQb64(qb64: string): Uint8Array | null {
  return decodeMatterRaw(qb64, "D", 32);
}

function nfc(value: string): string {
  return value.normalize("NFC");
}

function jsonField(key: string, value: unknown): string {
  if (value === undefined) return "";
  return `"${key}":${JSON.stringify(value)}`;
}

/** Canonical challenge body (sig excluded) per the login contract field order. */
export function canonicalChallengeBody(challenge: LoginChallenge): string {
  const parts = [
    jsonField("v", challenge.v),
    jsonField("t", challenge.t),
    jsonField("site_aid", nfc(challenge.site_aid)),
    jsonField("site_oobi", nfc(challenge.site_oobi)),
    jsonField("audience", nfc(challenge.audience)),
    jsonField("nonce", challenge.nonce),
    jsonField("dt", challenge.dt),
    jsonField("expiry", challenge.expiry),
    jsonField("requested_disclosures", challenge.requested_disclosures),
    jsonField("requested_credentials", challenge.requested_credentials),
  ];
  if (challenge.requested_score !== undefined) {
    parts.push(jsonField("requested_score", challenge.requested_score));
  }
  // Relationship anchor (org-owned membership-gated assets) is part of the
  // signed body — mirrors the Go canonicalizer. Omitted when absent so
  // pre-anchor challenges keep their original canonical form.
  if (challenge.relationship_anchor_aid) {
    parts.push(
      jsonField("relationship_anchor_aid", nfc(challenge.relationship_anchor_aid)),
      jsonField("relationship_anchor_oobi", nfc(challenge.relationship_anchor_oobi ?? "")),
    );
  }
  parts.push(
    jsonField("callback_url", nfc(challenge.callback_url)),
    jsonField("session_token", challenge.session_token),
  );
  return `{${parts.filter(Boolean).join(",")}}`;
}

/** Canonical assertion body (sig excluded) per the login contract field order. */
export function canonicalAssertionBody(assertion: LoginAssertion): string {
  const parts = [
    jsonField("v", assertion.v),
    jsonField("t", assertion.t),
    jsonField("d", assertion.d),
    jsonField("i", nfc(assertion.i)),
    jsonField("relationship_aid_oobi", nfc(assertion.relationship_aid_oobi)),
    jsonField("audience", nfc(assertion.audience)),
    jsonField("nonce", assertion.nonce),
    jsonField("dt", assertion.dt),
    jsonField("disclosures", assertion.disclosures),
    jsonField("presented_acdcs", assertion.presented_acdcs),
  ];
  if (assertion.custom_data !== undefined) {
    parts.push(jsonField("custom_data", assertion.custom_data));
  }
  if (assertion.p_kel !== undefined) {
    parts.push(jsonField("p_kel", assertion.p_kel));
  }
  return `{${parts.filter(Boolean).join(",")}}`;
}

export function assertionDigest(assertion: Omit<LoginAssertion, "d" | "sig">): string {
  const tmp = { ...assertion } as LoginAssertion & { d?: string };
  delete tmp.d;
  const body = canonicalAssertionBody(tmp);
  return blake3Qb64(new TextEncoder().encode(body));
}

export async function signCanonical(
  body: string,
  privateKey: Uint8Array,
): Promise<string> {
  const sig = await ed.signAsync(new TextEncoder().encode(body), privateKey);
  return ed25519SigQb64(sig);
}

export function decodeMatterRaw(qb64: string, code: string, expectedLen: number): Uint8Array | null {
  if (!qb64.startsWith(code)) return null;
  const cs = code.length;
  const ps = cs % 4;
  const paw = Buffer.from("A".repeat(ps) + qb64.slice(cs), "base64url");
  const raw = paw.slice(ps);
  if (raw.length !== expectedLen) return null;
  return new Uint8Array(raw);
}

export async function verifyCanonical(
  body: string,
  sigQb64: string,
  publicKey: Uint8Array,
): Promise<boolean> {
  const raw = decodeMatterRaw(sigQb64, "0B", 64);
  if (!raw) return false;
  return ed.verifyAsync(raw, new TextEncoder().encode(body), publicKey);
}

export function randomToken(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Buffer.from(buf).toString("base64url");
}

export function rfc3339Utc(secondsFromNow = 0): string {
  const d = new Date(Date.now() + secondsFromNow * 1000);
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function parseRfc3339(dt: string): number {
  return Date.parse(dt.endsWith("Z") ? dt : `${dt}Z`);
}