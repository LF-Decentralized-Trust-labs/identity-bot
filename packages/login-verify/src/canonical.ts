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

/** A non-transferable Ed25519 identifier (code B). The identifier is the key
 *  itself, so anyone holding it can check a signature made under it without a
 *  key log; the price is that its key can never rotate. */
export function nonTransferableAidQb64(pub: Uint8Array): string {
  return matterFixedQb64("B", pub);
}

export function decodeVerkeyQb64(qb64: string): Uint8Array | null {
  return decodeMatterRaw(qb64, "D", 32);
}

const BASE64URL = /^[A-Za-z0-9_-]*$/;

/** Decodes unpadded base64url with exactly one spelling per value: the
 *  base64url alphabet only, no padding, and the bits left over in the last
 *  character zero. `size`, when given, is the exact number of bytes required.
 *  Anything else is refused rather than read leniently. */
export function decodeBase64UrlStrict(s: unknown, size?: number): Uint8Array | null {
  if (typeof s !== "string" || !BASE64URL.test(s) || s.length % 4 === 1) return null;
  const raw = Buffer.from(s, "base64url");
  if (size !== undefined && raw.length !== size) return null;
  if (raw.toString("base64url") !== s) return null;
  return new Uint8Array(raw);
}

/** Decodes fixed-size CESR material under exactly one code, as the core does:
 *  the exact length the code and size make, base64url only, the lead bytes
 *  the code stands in for all zero, and nothing that re-encodes to another
 *  string. Read leniently, one signature had many strings that all verified. */
export function decodeMatterRaw(qb64: unknown, code: string, expectedLen: number): Uint8Array | null {
  if (typeof qb64 !== "string" || !code) return null;
  const ps = (3 - (expectedLen % 3)) % 3;
  // A fixed-size code takes the place of exactly the characters its lead
  // bytes produce, so the code length decides the lead and the total length.
  if (code.length % 4 !== ps) return null;
  if (qb64.length !== ((ps + expectedLen) / 3) * 4 + code.length - ps) return null;
  if (!qb64.startsWith(code) || !BASE64URL.test(qb64)) return null;
  const paw = Buffer.from("A".repeat(ps) + qb64.slice(code.length), "base64url");
  if (paw.length !== ps + expectedLen) return null;
  for (let k = 0; k < ps; k++) if (paw[k] !== 0) return null;
  const raw = new Uint8Array(paw.subarray(ps));
  if (matterFixedQb64(code, raw) !== qb64) return null;
  return raw;
}

/** Thrown when a value cannot be canonicalised because the core would not
 *  have read it at all: a number where text belongs, an object where a list
 *  belongs. A verifier treats it as a refusal. */
export class CanonicalFormError extends Error {}

// The canonical bodies below are the core's (`login/canonical.go`) byte for
// byte. The core reads an assertion into typed fields and writes each with
// encoding/json, so these follow encoding/json's rules rather than
// JSON.stringify's: map keys sorted by their UTF-8 bytes, struct fields in
// their declared order, "<", ">", "&", U+2028 and U+2029 escaped, unpaired
// surrogates replaced by U+FFFD, and every field the core declares written
// even when absent ("" for text, null for a list or map). Strings are signed
// exactly as given, never normalised: normalising here would let a second
// spelling of a signed string verify.

const UNPAIRED_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

function wellFormed(s: string): string {
  return s.replace(UNPAIRED_SURROGATE, "\uFFFD");
}

function goString(s: string): string {
  return JSON.stringify(wellFormed(s))
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

function goNumber(n: number): string {
  if (!Number.isFinite(n)) throw new CanonicalFormError("a number must be finite");
  // JavaScript and Go switch to exponent notation at the same magnitudes and
  // both write the shortest digits that round-trip; only negative zero differs.
  return Object.is(n, -0) ? "-0" : String(n);
}

function utf8Order(a: string, b: string): number {
  return Buffer.compare(Buffer.from(wellFormed(a)), Buffer.from(wellFormed(b)));
}

/** Any JSON value, as encoding/json writes an `interface{}` holding it. */
function goJson(value: unknown): string {
  if (value === null || value === undefined) return "null";
  switch (typeof value) {
    case "string":
      return goString(value);
    case "number":
      return goNumber(value);
    case "boolean":
      return value ? "true" : "false";
    case "object":
      if (Array.isArray(value)) return `[${value.map(goJson).join(",")}]`;
      return goMap(value as Record<string, unknown>, goJson);
    default:
      throw new CanonicalFormError(`a ${typeof value} is not JSON`);
  }
}

function goMap(obj: Record<string, unknown>, each: (v: unknown) => string): string {
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort(utf8Order);
  return `{${keys.map((k) => `${goString(k)}:${each(obj[k])}`).join(",")}}`;
}

function isMap(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** A Go `string` field: null or absent reads as "". */
function str(v: unknown, field: string): string {
  if (v === null || v === undefined) return "";
  if (typeof v !== "string") throw new CanonicalFormError(`${field} must be text`);
  return v;
}

function bool(v: unknown, field: string): boolean {
  if (v === null || v === undefined) return false;
  if (typeof v !== "boolean") throw new CanonicalFormError(`${field} must be true or false`);
  return v;
}

function int(v: unknown, field: string): number {
  if (v === null || v === undefined) return 0;
  if (typeof v !== "number" || !Number.isSafeInteger(v)) {
    throw new CanonicalFormError(`${field} must be a whole number`);
  }
  return v;
}

/** A Go slice: null or absent is written null. */
function list(v: unknown, field: string, each: (e: unknown) => string): string {
  if (v === null || v === undefined) return "null";
  if (!Array.isArray(v)) throw new CanonicalFormError(`${field} must be a list`);
  return `[${v.map(each).join(",")}]`;
}

function field(key: string, json: string): string {
  return `"${key}":${json}`;
}

function textField(key: string, v: unknown): string {
  return field(key, goString(str(v, key)));
}

/** Canonical challenge body (sig excluded) per the login contract field order. */
export function canonicalChallengeBody(challenge: LoginChallenge): string {
  const c = challenge as unknown as Record<string, unknown>;
  const parts = [
    textField("v", c.v),
    field("t", goNumber(int(c.t, "t"))),
    textField("site_aid", c.site_aid),
    textField("site_oobi", c.site_oobi),
    textField("audience", c.audience),
    textField("nonce", c.nonce),
    textField("dt", c.dt),
    textField("expiry", c.expiry),
    field(
      "requested_disclosures",
      list(c.requested_disclosures, "requested_disclosures", (e) => goString(str(e, "requested_disclosures"))),
    ),
    field(
      "requested_credentials",
      list(c.requested_credentials, "requested_credentials", (e) => {
        if (e !== null && !isMap(e)) throw new CanonicalFormError("a requested credential must be an object");
        const rc = e ?? {};
        return `{${textField("schema_said", rc.schema_said)},${field("required", String(bool(rc.required, "required")))}}`;
      }),
    ),
  ];
  if (c.requested_score !== null && c.requested_score !== undefined) {
    if (!isMap(c.requested_score)) throw new CanonicalFormError("requested_score must be an object");
    // Every field of the requested score is omitted when it holds its zero value.
    const rs = c.requested_score;
    const score: string[] = [];
    const band = str(rs.min_band, "min_band");
    if (band !== "") score.push(field("min_band", goString(band)));
    const min = int(rs.min_score, "min_score");
    if (min !== 0) score.push(field("min_score", goNumber(min)));
    if (bool(rs.required, "required")) score.push(field("required", "true"));
    parts.push(field("requested_score", `{${score.join(",")}}`));
  }
  // The relationship anchor (membership-gated assets) is part of the signed
  // body. Omitted when absent so pre-anchor challenges keep their original
  // canonical form.
  if (str(c.relationship_anchor_aid, "relationship_anchor_aid") !== "") {
    parts.push(
      textField("relationship_anchor_aid", c.relationship_anchor_aid),
      textField("relationship_anchor_oobi", c.relationship_anchor_oobi),
    );
  }
  parts.push(textField("callback_url", c.callback_url), textField("session_token", c.session_token));
  return `{${parts.join(",")}}`;
}

/** Canonical assertion body (sig excluded) per the login contract field order. */
export function canonicalAssertionBody(assertion: LoginAssertion): string {
  const a = assertion as unknown as Record<string, unknown>;
  const parts = [textField("v", a.v), textField("t", a.t)];
  // d is left out while it is being computed ("body minus d and sig").
  if (str(a.d, "d") !== "") parts.push(textField("d", a.d));
  parts.push(
    textField("i", a.i),
    textField("relationship_aid_oobi", a.relationship_aid_oobi),
    textField("audience", a.audience),
    textField("nonce", a.nonce),
    textField("dt", a.dt),
  );
  if (a.disclosures === null || a.disclosures === undefined) {
    parts.push(field("disclosures", "null"));
  } else {
    if (!isMap(a.disclosures)) throw new CanonicalFormError("disclosures must be an object");
    parts.push(field("disclosures", goMap(a.disclosures, (v) => goString(str(v, "a disclosure")))));
  }
  parts.push(field("presented_acdcs", list(a.presented_acdcs, "presented_acdcs", goJson)));
  if (a.custom_data !== null && a.custom_data !== undefined) {
    if (!isMap(a.custom_data)) throw new CanonicalFormError("custom_data must be an object");
    parts.push(field("custom_data", goJson(a.custom_data)));
  }
  if (str(a.p_kel, "p_kel") !== "") parts.push(textField("p_kel", a.p_kel));
  if (str(a.site_aid, "site_aid") !== "") parts.push(textField("site_aid", a.site_aid));
  return `{${parts.join(",")}}`;
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

export async function verifyCanonical(
  body: string,
  sigQb64: string,
  publicKey: Uint8Array,
): Promise<boolean> {
  const raw = decodeMatterRaw(sigQb64, "0B", 64);
  if (!raw) return false;
  return verifyEd25519(raw, new TextEncoder().encode(body), publicKey);
}

/** Ed25519 verification under RFC 8032's rules rather than ZIP-215's: a
 *  non-canonical point encoding is refused, so a signature cannot be
 *  respelled into another that still verifies. Malformed input is a refusal,
 *  never a throw. */
export async function verifyEd25519(
  sig: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  if (sig.length !== 64 || publicKey.length !== 32) return false;
  try {
    return await ed.verifyAsync(sig, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
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

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

/** Milliseconds since the epoch for an RFC 3339 timestamp, or NaN for
 *  anything that is not one (a missing zone included). */
export function parseRfc3339(dt: unknown): number {
  if (typeof dt !== "string" || !RFC3339.test(dt)) return NaN;
  return Date.parse(dt);
}
