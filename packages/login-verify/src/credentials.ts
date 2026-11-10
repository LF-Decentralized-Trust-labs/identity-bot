import { blake3Qb64 } from "./canonical.js";

// The credentials a sign-in presents (ADR-071). The assertion signs a digest
// for each; the credentials themselves arrive beside it, unsigned, for the
// website owner's server. This is the rule that decides which of them count,
// the same as `BoundCredentials` in the core's login package, and held to it by
// the shared vectors (`sign_in_posts`).

const SAID_LEN = 44;
const DUMMY = "#".repeat(SAID_LEN);
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

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

/** Where the compact JSON value starting at `i` in `text` ends, or -1. Compact
 *  means no whitespace anywhere outside a string, and the grammar is JSON's:
 *  what Go's json.Compact leaves unchanged. */
function valueEnd(text: string, i: number): number {
  const c = text[i];
  if (c === '"') {
    let j = i + 1;
    while (j < text.length) {
      const d = text[j];
      if (d === '"') return j + 1;
      if (d < " ") return -1;
      if (d === "\\") {
        const e = text[j + 1];
        if (e === "u") {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(j + 2, j + 6))) return -1;
          j += 6;
        } else if (e !== undefined && '"\\/bfnrt'.includes(e)) j += 2;
        else return -1;
      } else j++;
    }
    return -1;
  }
  if (c === "{" || c === "[") {
    const close = c === "{" ? "}" : "]";
    let j = i + 1;
    if (text[j] === close) return j + 1;
    for (;;) {
      if (c === "{") {
        if (text[j] !== '"') return -1;
        const k = valueEnd(text, j);
        if (k < 0 || text[k] !== ":") return -1;
        j = k + 1;
      }
      const e = valueEnd(text, j);
      if (e < 0) return -1;
      j = e;
      if (text[j] === ",") j++;
      else return text[j] === close ? j + 1 : -1;
    }
  }
  const lit = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(i, i + 400));
  if (!lit) return -1;
  // A number longer than the window is read as far as the window: nothing in a
  // credential is that long, and a longer one is refused below as not ending.
  return i + lit[0].length;
}

/** The key as Go's encoder writes it (HTML escaping off), which is the only
 *  spelling of a key the core reads back unchanged. */
function canonicalKey(key: string): string {
  let out = '"';
  for (const ch of key) {
    const n = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (n < 0x20 || n === 0x2028 || n === 0x2029) out += "\\u" + n.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

/** The members of the JSON object `text` at its top level: each key with the
 *  span of its value. The object must be in the one spelling the core reads
 *  (compact, each key as the core writes it) and no key may repeat, since which
 *  of two a reader sees would differ between readers. Null on anything else. */
function topLevelMembers(text: string): Array<{ key: string; start: number; end: number }> | null {
  if (text[0] !== "{") return null;
  const out: Array<{ key: string; start: number; end: number }> = [];
  const seen = new Set<string>();
  let i = 1;
  if (text[i] === "}") return text.length === 2 ? out : null;
  for (;;) {
    const kEnd = text[i] === '"' ? valueEnd(text, i) : -1;
    if (kEnd < 0 || text[kEnd] !== ":") return null;
    let key: string;
    try {
      key = JSON.parse(text.slice(i, kEnd)) as string;
    } catch {
      return null;
    }
    if (text.slice(i, kEnd) !== canonicalKey(key) || seen.has(key)) return null;
    seen.add(key);
    const start = kEnd + 1;
    const end = valueEnd(text, start);
    if (end < 0) return null;
    out.push({ key, start, end });
    i = end;
    if (text[i] === ",") i++;
    else return text[i] === "}" && i === text.length - 1 ? out : null;
  }
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
  // The version string, which states the size, is one of the two spellings the
  // core writes, and states the size the body is.
  const v = /^\{"v":"ACDC(?:10JSON([0-9a-f]{6})_|CAAJSON([A-Za-z0-9_-]{4})\.)","/.exec(text);
  if (!v) return null;
  const declared =
    v[1] !== undefined ? parseInt(v[1], 16) : [...v[2]].reduce((n, c) => n * 64 + B64.indexOf(c), 0);
  if (declared !== raw.length) return null;
  const members = topLevelMembers(text);
  if (!members) return null;
  // The core reads a credential that names its issuer and its schema, and
  // nothing else.
  const str = (key: string): string | null => {
    const m = members.find((x) => x.key === key);
    if (!m) return null;
    try {
      const x: unknown = JSON.parse(text.slice(m.start, m.end));
      return typeof x === "string" && x !== "" ? x : null;
    } catch {
      return null;
    }
  };
  if (str("i") === null || str("s") === null) return null;
  const whole = blankedD(text);
  if (!whole || blake3Qb64(new TextEncoder().encode(whole.blanked)) !== whole.said) return null;
  const a = members.find((m) => m.key === "a");
  const block = a ? blankedD(text.slice(a.start, a.end)) : null;
  if (!block || blake3Qb64(new TextEncoder().encode(block.blanked)) !== block.said) return null;
  return whole.said;
}

/** The schema and the issuer a credential's body names: what the core reads
 *  out of it, and what a site's server must read, never what a poster wrote
 *  beside it. Null if the body is not one the core reads. */
export function credentialFields(acdcJsonB64: string): { said: string; schema: string; issuer: string } | null {
  const said = credentialSaid(acdcJsonB64);
  if (said === null) return null;
  const text = new TextDecoder().decode(decodeBase64(acdcJsonB64)!);
  const members = topLevelMembers(text)!;
  const read = (key: string): string => {
    const m = members.find((x) => x.key === key)!;
    return JSON.parse(text.slice(m.start, m.end)) as string;
  };
  return { said, schema: read("s"), issuer: read("i") };
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
    if (!isMap(c) || typeof c.said !== "string" || !named.has(c.said) || typeof c.acdc_json_b64 !== "string") continue;
    const body = credentialFields(c.acdc_json_b64);
    if (body === null || body.said !== c.said) continue;
    // The schema and the issuer come from the body, as the core reads them,
    // never from what the poster wrote beside it.
    const text = (k: string): string => (typeof c[k] === "string" ? (c[k] as string) : "");
    out.push({
      said: c.said,
      schema_said: body.schema,
      issuer_aid: body.issuer,
      holder_aid: text("holder_aid"),
      status: text("status"),
      acdc_json_b64: c.acdc_json_b64,
      pres_said_b64: text("pres_said_b64"),
      cesr_sig: text("cesr_sig"),
      holder_public_key: text("holder_public_key"),
    });
  }
  return out;
}
