import { blake3Qb64 } from "./canonical.js";

// The credentials a sign-in presents (ADR-071). The assertion signs a digest
// for each; the credentials themselves arrive beside it, unsigned, for the
// website owner's server. This is the rule that decides which of them count,
// the same as `BoundCredentials` in the core's login package, and held to it by
// the shared vectors (`sign_in_posts`).

const SAID_LEN = 44;
const DUMMY = "#".repeat(SAID_LEN);

/** base64, standard or URL alphabet, padded or not: the spellings the core reads.
 *  Anything else, a line break included, is not a credential's body. */
function decodeBase64(s: string): Uint8Array | null {
  if (typeof s !== "string" || !/^[A-Za-z0-9+/_-]*={0,2}$/.test(s)) return null;
  const std = s.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (std.length % 4 === 1) return null;
  const padded = std + "=".repeat((4 - (std.length % 4)) % 4);
  try {
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/** The members of the JSON object `text` at its top level: each key with the
 *  span of its value. Compact JSON, as a credential is written; null on
 *  anything else. */
function topLevelMembers(text: string): Array<{ key: string; start: number; end: number }> | null {
  if (text[0] !== "{") return null;
  const out: Array<{ key: string; start: number; end: number }> = [];
  let i = 1;
  const readString = (): string | null => {
    if (text[i] !== '"') return null;
    const from = i;
    i++;
    while (i < text.length && text[i] !== '"') i += text[i] === "\\" ? 2 : 1;
    if (i >= text.length) return null;
    i++;
    try {
      return JSON.parse(text.slice(from, i)) as string;
    } catch {
      return null;
    }
  };
  while (i < text.length) {
    if (text[i] === "}") return i === text.length - 1 ? out : null;
    const key = readString();
    if (key === null || text[i] !== ":") return null;
    i++;
    const start = i;
    let depth = 0;
    while (i < text.length) {
      const c = text[i];
      if (c === '"') {
        if (readString() === null) return null;
        continue;
      }
      if (c === "{" || c === "[") depth++;
      else if (c === "}" || c === "]") {
        if (depth === 0) break;
        depth--;
      } else if (c === "," && depth === 0) break;
      i++;
    }
    out.push({ key, start, end: i });
    if (text[i] === ",") i++;
  }
  return null;
}

/** `text` with the value of its member `d` blanked, and that value; null if `d`
 *  is not a 44-character string. */
function blankedD(text: string): { blanked: string; said: string } | null {
  const members = topLevelMembers(text);
  const d = members?.find((m) => m.key === "d");
  if (!d) return null;
  const value = text.slice(d.start, d.end);
  if (value.length !== SAID_LEN + 2 || value[0] !== '"' || value[value.length - 1] !== '"') return null;
  const said = value.slice(1, -1);
  if (said.includes("\\") || said.includes('"')) return null;
  return { blanked: text.slice(0, d.start + 1) + DUMMY + text.slice(d.end - 1), said };
}

/** The SAID a credential's body has, if its bytes are the canonical writing of a
 *  credential that carries it: the digest of the body with its `d` blanked, and
 *  of its attribute block with that block's own `d` blanked, each equal to what
 *  it says. Null otherwise. `acdcJsonB64` is the body as the person's Identity
 *  Agent sends it (`acdc_json_b64`). */
export function credentialSaid(acdcJsonB64: string): string | null {
  const raw = decodeBase64(acdcJsonB64);
  if (!raw) return null;
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw);
  } catch {
    return null;
  }
  if (!/^\{"v":"ACDC[0-9a-zA-Z]+_","d":"/.test(text)) return null;
  const whole = blankedD(text);
  if (!whole || blake3Qb64(new TextEncoder().encode(whole.blanked)) !== whole.said) return null;
  const a = topLevelMembers(text)?.find((m) => m.key === "a");
  const block = a ? blankedD(text.slice(a.start, a.end)) : null;
  if (!block || blake3Qb64(new TextEncoder().encode(block.blanked)) !== block.said) return null;
  return whole.said;
}

function isMap(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** The credentials an assertion presents, as a site's server may read them: a
 *  posted credential is kept only if the assertion names its SAID (as a digest in
 *  `presented_acdcs`) and the body it carries has that SAID. One posted but not
 *  named is left out; a digest with no credential posted presents nothing. An
 *  assertion in the form before ADR-071 carries its credentials whole, and they
 *  are returned as they were. */
export function boundCredentials(presented: unknown[], posted: unknown[]): unknown[] {
  const named = new Set<string>();
  const out: unknown[] = [];
  for (const p of presented ?? []) {
    if (typeof p === "string") named.add(p);
    else out.push(p);
  }
  for (const c of posted ?? []) {
    if (!isMap(c) || typeof c.said !== "string" || !named.has(c.said)) continue;
    if (typeof c.acdc_json_b64 !== "string" || credentialSaid(c.acdc_json_b64) !== c.said) continue;
    out.push(c);
  }
  return out;
}
