/**
 * Sealed front-end traffic, ADR-072 section 2 step 5 and Amendment 4: what a
 * utility app's page does so the relay between it and the app's back end reads
 * nothing but "somebody called, this big, now".
 *
 * Every call is one POST to one fixed path (`SEAL_PATH`) whose body is
 * `{"v":1,"epk":<P-256 point>,"ct":<ciphertext>}`; every answer is one 200 whose
 * body is `{"v":1,"n":<16 to 32 random bytes>,"ct":<ciphertext>}`. The page makes a
 * fresh P-256 key for each call and agrees a secret with the back end's sealing
 * key (ECDH). HKDF-SHA256, salted by epk||sealing key (and, for the answer, the
 * back end's own random `n`), gives each direction its own AES-256-GCM key and
 * nonce. The answer does not rely on epk being fresh: `n` is the back end's, so
 * two answers to one call never share a key and nonce. The version, relay
 * identifier, direction and epk (and `n`) are the associated data. The plaintext is its length (4 bytes, big-endian), the
 * content, then zeros up to a bucket (1024 bytes, doubling), so the relay sees
 * only the bucket.
 *
 * This is the TypeScript half of `packages/login-go/seal.go`; the two are held
 * to `test-vectors/seal.json`. What the content is (the call, its proof, the
 * answer and the app's signature on it) is `app.ts`'s; this module only seals
 * and opens bytes. It reads nothing but WebCrypto.
 */

export const SEAL_PATH = "/sealed";
/** Where the sealing key statement now in force is fetched (login-go's `SealStatementPath`). */
export const SEAL_STATEMENT_PATH = "/sealing-key";
/** True for the outer answer a back end gives a call it could not open: 400 and exactly
 *  `{"error":"sealing key"}` (login-go's `SealingKeyStatus`, `SealingKeyAnswer`; the `sealing_key_answer`
 *  case in seal.json). It is unsigned, and is taken only as a reason to fetch the statement and check it. */
export function isSealingKeyAnswer(status: number, body: string): boolean {
  return status === 400 && body === '{"error":"sealing key"}';
}
export const SEAL_VERSION = 1;
export const SEAL_BUCKET = 1024;
export const SEAL_MAX = 16 << 20;

const utf8 = new TextEncoder();
const LABEL = "APP-SEAL-V1";

export function b64u(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Strict base64url: no padding, no other alphabet; null if it is not. */
export function unb64u(text: unknown): Uint8Array | null {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return null;
  const s = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  const out = Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  return b64u(out) === text ? out : null;
}

/** Every refusal of a sealed message: it says nothing about why. */
export class SealError extends Error {
  constructor() {
    super("the sealed message is not accepted");
    this.name = "SealError";
  }
}

function bucketFor(n: number): number {
  let b = SEAL_BUCKET;
  while (b < n + 4) b *= 2;
  return b;
}

function pad(content: Uint8Array): Uint8Array {
  if (content.length > SEAL_MAX) throw new SealError();
  const out = new Uint8Array(bucketFor(content.length));
  new DataView(out.buffer).setUint32(0, content.length);
  out.set(content, 4);
  return out;
}

function unpad(p: Uint8Array): Uint8Array {
  if (p.length < 4) throw new SealError();
  const n = new DataView(p.buffer, p.byteOffset, p.byteLength).getUint32(0);
  if (n > p.length - 4 || n > SEAL_MAX || p.length !== bucketFor(n)) throw new SealError();
  for (let i = 4 + n; i < p.length; i++) if (p[i] !== 0) throw new SealError();
  return p.slice(4, 4 + n);
}

const aad = (rid: string, dir: string, epk: Uint8Array, n?: Uint8Array) =>
  utf8.encode(`${LABEL}\n${rid}\n${dir}\n${SEAL_VERSION}\n${b64u(epk)}` + (n ? `\n${b64u(n)}` : ""));

export const ANSWER_N_MIN = 16;
export const ANSWER_N_MAX = 32;

async function hkdf(secret: Uint8Array, salt: Uint8Array, info: string, bytes: number): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", secret as BufferSource, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: salt as BufferSource, info: utf8.encode(info) }, k, bytes * 8));
}

async function direction(secret: Uint8Array, epk: Uint8Array, spk: Uint8Array, rid: string, dir: string, n?: Uint8Array) {
  const salt = new Uint8Array([...epk, ...spk, ...(n ?? [])]);
  return {
    key: await hkdf(secret, salt, `${LABEL} ${dir} key\n${rid}`, 32),
    nonce: await hkdf(secret, salt, `${LABEL} ${dir} nonce\n${rid}`, 12),
    aad: aad(rid, dir, epk, n),
  };
}

type Dir = { key: Uint8Array; nonce: Uint8Array; aad: Uint8Array };

async function encryptPadded(d: Dir, padded: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", d.key as BufferSource, "AES-GCM", false, ["encrypt"]);
  return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: d.nonce as BufferSource, additionalData: d.aad as BufferSource }, k, padded as BufferSource));
}

async function sealWith(d: Dir, content: Uint8Array): Promise<Uint8Array> {
  return encryptPadded(d, pad(content));
}

async function openWith(d: Dir, ct: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", d.key as BufferSource, "AES-GCM", false, ["decrypt"]);
  let p: Uint8Array;
  try {
    p = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: d.nonce as BufferSource, additionalData: d.aad as BufferSource }, k, ct as BufferSource));
  } catch {
    throw new SealError();
  }
  return unpad(p);
}

/** What one sealed call leaves behind to open (or, at the back end, seal) its answer. */
export interface Reply {
  /** `n` is for the vectors; an answer makes its own 32 random bytes. */
  seal(content: Uint8Array, n?: Uint8Array): Promise<string>;
  open(outer: string): Promise<Uint8Array>;
}

function reply(secret: Uint8Array, epk: Uint8Array, spk: Uint8Array, rid: string): Reply {
  return {
    async seal(content, n) {
      const nn = n ?? crypto.getRandomValues(new Uint8Array(ANSWER_N_MAX));
      if (nn.length < ANSWER_N_MIN || nn.length > ANSWER_N_MAX) throw new SealError();
      const d = await direction(secret, epk, spk, rid, "answer", nn);
      return JSON.stringify({ v: SEAL_VERSION, n: b64u(nn), ct: b64u(await sealWith(d, content)) });
    },
    async open(outer) {
      let o: { v?: unknown; n?: unknown; ct?: unknown };
      try {
        o = JSON.parse(outer);
      } catch {
        throw new SealError();
      }
      const n = unb64u(o?.n);
      const ct = unb64u(o?.ct);
      if (Object.keys(o ?? {}).sort().join(",") !== "ct,n,v" || o.v !== SEAL_VERSION || !ct || !n || n.length < ANSWER_N_MIN || n.length > ANSWER_N_MAX) throw new SealError();
      return openWith(await direction(secret, epk, spk, rid, "answer", n), ct);
    },
  };
}

/** Seals `content` (a call) for the back end whose sealing key is `spk` (65
 *  bytes), as the relay identifier `rid`. `eph` is for the vectors; a call
 *  makes its own. Returns the body to POST to `SEAL_PATH` and the Reply that
 *  opens its answer. */
export async function sealRequest(rid: string, spk: Uint8Array, content: Uint8Array, eph?: CryptoKeyPair): Promise<{ outer: string; reply: Reply }> {
  let pub: CryptoKey;
  try {
    pub = await crypto.subtle.importKey("raw", spk as BufferSource, { name: "ECDH", namedCurve: "P-256" }, false, []);
  } catch {
    throw new SealError();
  }
  const pair = eph ?? (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]));
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, pair.privateKey, 256));
  const epk = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const ct = await sealWith(await direction(secret, epk, spk, rid, "request"), content);
  return {
    outer: JSON.stringify({ v: SEAL_VERSION, epk: b64u(epk), ct: b64u(ct) }),
    reply: reply(secret, epk, spk, rid),
  };
}

/** For vectors only: a call whose plaintext is exactly `padded`, not made by
 *  `pad`, so a back end can be shown refusing a size or padding no honest
 *  sealer makes. */
export async function sealPaddedRequestForVectors(rid: string, spk: Uint8Array, padded: Uint8Array, eph: CryptoKeyPair): Promise<string> {
  const pub = await crypto.subtle.importKey("raw", spk as BufferSource, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, eph.privateKey, 256));
  const epk = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const ct = await encryptPadded(await direction(secret, epk, spk, rid, "request"), padded);
  return JSON.stringify({ v: SEAL_VERSION, epk: b64u(epk), ct: b64u(ct) });
}

/** For the vectors only: a correctly sealed answer (the one real key and nonce, authenticated
 *  and all) whose `n` is of any length, so a reader can be shown refusing one that is out of
 *  bounds for that alone. `Reply.seal` refuses such an `n`, as no honest back end makes one. */
export async function sealAnswerWithAnyNForVectors(rid: string, spk: Uint8Array, eph: CryptoKeyPair, n: Uint8Array, content: Uint8Array): Promise<string> {
  const pub = await crypto.subtle.importKey("raw", spk as BufferSource, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, eph.privateKey, 256));
  const epk = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const d = await direction(secret, epk, spk, rid, "answer", n);
  return JSON.stringify({ v: SEAL_VERSION, n: b64u(n), ct: b64u(await sealWith(d, content)) });
}

/** The back end's side, for tests and vectors: opens a sealed call with the
 *  sealing key's private half and returns the content and the Reply that seals
 *  its answer. A real back end is `login-go`'s `SealKey.OpenRequest`. */
export async function openRequest(rid: string, key: CryptoKeyPair, outer: string): Promise<{ content: Uint8Array; reply: Reply }> {
  let o: { v?: unknown; epk?: unknown; ct?: unknown };
  try {
    o = JSON.parse(outer);
  } catch {
    throw new SealError();
  }
  const epk = unb64u(o?.epk);
  const ct = unb64u(o?.ct);
  if (Object.keys(o ?? {}).sort().join(",") !== "ct,epk,v" || o.v !== SEAL_VERSION || !epk || !ct) throw new SealError();
  let pub: CryptoKey;
  try {
    pub = await crypto.subtle.importKey("raw", epk as BufferSource, { name: "ECDH", namedCurve: "P-256" }, false, []);
  } catch {
    throw new SealError();
  }
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, key.privateKey, 256));
  const spk = new Uint8Array(await crypto.subtle.exportKey("raw", key.publicKey));
  const content = await openWith(await direction(secret, epk, spk, rid, "request"), ct);
  return { content, reply: reply(secret, epk, spk, rid) };
}

/** What the relay identifier's key signs to vouch for a sealing key: the identifier, the
 *  sequence number of the event of its key log whose key signs, and the key. */
export function sealKeyStatementText(rid: string, pub: Uint8Array, sn: number): Uint8Array {
  return utf8.encode(`APP-SEAL-KEY-V1\n${rid}\n${sn}\n${b64u(pub)}`);
}
