/**
 * The statement a person's browser key signs over a salted fingerprint of their words, never the words (ADR-067), in the
 * form the Identity Agent's core checks: `agentmessage.PersonStatement` is the one definition, and this reads it. What
 * must stay the same as the core's is the string that is signed and the fingerprint, and both are held to the core's own
 * `signed-fingerprint-vectors.json` by `person-statement-vectors.test.mjs`.
 *
 * A utility app's hosted page signs with it what its person says (`ask`), closes or reopens a conversation, and lists
 * their conversations for one other utility app (`list`, which names that app as its audience, ADR-072 Amendment 8).
 * The key is the browser's, non-extractable, in this page's own IndexedDB: nothing here can read it out, only sign.
 */
import { blake3Qb64, matterFixedQb64 } from "@identity-agent/login-verify/browser";
import type { BrowserKey } from "./app.js";

export type PersonKind = "ask" | "close" | "reopen" | "list";

/** The statement as the core reads it: exactly its fields, a field with nothing in it left out. */
export interface PersonStatement {
  agent: string;
  conversation: string;
  message_id: string;
  kind: string;
  from: string;
  signer: string;
  to?: string;
  in_reply_to?: string;
  range_first?: string;
  range_last?: string;
  audience?: string;
  nonce: string;
  time: string;
  fingerprint_version: number;
  fingerprint: string;
}

/** `agentmessage.ListConversation`: a list is for no conversation, and nothing else is for "list". */
export const LIST_CONVERSATION = "list";

const enc = new TextEncoder();
const b64u = (b: Uint8Array): string => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64 = (s: string): Uint8Array => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

/** `IA-PERSON-MSG-V1` and then one field per line in the core's order, no newline at the end. A statement with an
 *  audience (a list) is `IA-PERSON-MSG-V2`: the same lines and the audience last. */
export function personStatementBytes(s: PersonStatement): string {
  const lines = [
    "IA-PERSON-MSG-V1", s.agent, s.conversation, s.message_id, s.kind, s.from, s.signer, s.to ?? "", s.in_reply_to ?? "",
    s.range_first ?? "", s.range_last ?? "", s.nonce, s.time, String(s.fingerprint_version), s.fingerprint,
  ];
  if (s.audience) {
    lines[0] = "IA-PERSON-MSG-V2";
    lines.push(s.audience);
  }
  return lines.join("\n");
}

/** `Blake3-256(tag ‖ salt_length ‖ salt ‖ words)` as a CESR `E` digest (`agentmessage.Fingerprint`). */
export function personFingerprint(salt: Uint8Array, words: string | Uint8Array): string {
  if (salt.length < 16 || salt.length > 1024) throw new Error("a salt is 16 to 1024 bytes");
  const tag = enc.encode("IA-FINGERPRINT-V1");
  const w = typeof words === "string" ? enc.encode(words) : words;
  const pre = new Uint8Array(tag.length + 2 + salt.length + w.length);
  pre.set(tag, 0);
  pre.set([salt.length >> 8, salt.length & 0xff], tag.length);
  pre.set(salt, tag.length + 2);
  pre.set(w, tag.length + 2 + salt.length);
  return blake3Qb64(pre);
}

/** The compressed point of the key (33 bytes): how the core names a P-256 key. */
function compressedPoint(jwk: { x: string; y: string }): Uint8Array {
  const x = unb64(jwk.x), y = unb64(jwk.y);
  if (x.length !== 32 || y.length !== 32) throw new Error("the browser key is not a P-256 key");
  const out = new Uint8Array(33);
  out[0] = (y[31]! & 1) === 1 ? 3 : 2;
  out.set(x, 1);
  return out;
}

/** The key's identifier (`signer`) in a statement. */
export const personSigner = (jwk: { x: string; y: string }): string => matterFixedQb64("1AAI", compressedPoint(jwk));
/** The key as a verification key. */
export const personVerkey = (jwk: { x: string; y: string }): string => matterFixedQb64("1AAJ", compressedPoint(jwk));

const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

/** A signature in the form the core accepts for a P-256 key: the low-s form (WebCrypto gives either, and a request is
 *  remembered by its signature, so the core takes one), as a CESR `0I` signature. `raw` is r then s, 32 bytes each. */
export function lowSSignature(raw: Uint8Array): string {
  if (raw.length !== 64) throw new Error("a P-256 signature is 64 bytes");
  let s = 0n;
  for (const b of raw.slice(32)) s = (s << 8n) | BigInt(b);
  if (s > N >> 1n) s = N - s;
  const out = new Uint8Array(64);
  out.set(raw.slice(0, 32), 0);
  for (let i = 63; i >= 32; i--) {
    out[i] = Number(s & 0xffn);
    s >>= 8n;
  }
  return matterFixedQb64("0I", out);
}

/** The core's `agentmessage.PersonProof`: the statement, the key that signed it and the signature. */
export interface PersonProof {
  statement: PersonStatement;
  verkey: string;
  signature: string;
}

/** What a page says about a statement it signs. The page, not its caller, decides every other field: the key, who the
 *  person is here (`from`), the id, the nonce, the time and the salt are made here, so whoever asks for a signature
 *  cannot ask for those. */
export interface StatementRequest {
  /** The Identity Agent that holds the conversation (it is signed in, so another Identity Agent refuses a copy). */
  agent: string;
  kind: PersonKind;
  /** The person's identifier at this utility app. */
  from: string;
  /** The conversation (not for a list). */
  conversation?: string;
  /** The identifier the words are to (an `ask`). */
  to?: string;
  /** The utility app's asset id a `list` is for (a `list`, and only a list). */
  audience?: string;
  /** The words (an `ask`); a close, a reopen and a list have none. */
  words?: string;
}

export interface SignedStatement {
  statement: PersonProof;
  /** The salt of the fingerprint, unpadded base64url. It travels with the words and is never in a record. */
  salt: string;
}

export interface SigningEnvironment {
  now?: () => Date;
  random?: (n: number) => Uint8Array;
}

const NO_BREAKS = /[\r\n]/;

/** Signs one statement with the browser's key. Refuses what the core would: a list that names no audience, or any
 *  other kind that names one, a list for a conversation, an ask with no words or no recipient, a close or reopen with
 *  words or a recipient, and a field with a line break in it. */
export async function signPersonStatement(key: BrowserKey, r: StatementRequest, env: SigningEnvironment = {}): Promise<SignedStatement> {
  const words = r.words ?? "";
  const isList = r.kind === "list";
  const conversation = isList ? LIST_CONVERSATION : r.conversation ?? "";
  if (!["ask", "close", "reopen", "list"].includes(r.kind)) throw new Error("a page signs an ask, a close, a reopen or a list");
  if (isList !== !!r.audience) throw new Error("a statement names an audience if and only if it is a list");
  if (!isList && !conversation) throw new Error("name the conversation");
  if (isList && r.conversation) throw new Error("a list is for no conversation");
  if (r.kind === "ask" && (!r.to || !words)) throw new Error("an ask names who it is to, and has words");
  if (r.kind !== "ask" && (r.to || words)) throw new Error("only an ask has a recipient and words");
  if (!r.agent || !r.from) throw new Error("name the Identity Agent and the person");
  for (const v of [r.agent, r.from, conversation, r.to ?? "", r.audience ?? ""]) if (NO_BREAKS.test(v)) throw new Error("a statement field may not contain a line break");
  const random = env.random ?? ((n: number) => crypto.getRandomValues(new Uint8Array(n)));
  const now = (env.now ?? (() => new Date()))();
  const salt = random(16);
  const id = "m-" + b64u(random(12));
  const st: PersonStatement = {
    agent: r.agent, conversation, message_id: id, kind: r.kind, from: r.from, signer: personSigner(key.jwk),
    ...(r.to ? { to: r.to } : {}), ...(r.audience ? { audience: r.audience } : {}),
    nonce: "n-" + b64u(random(12)), time: now.toISOString().replace(/\.\d+Z$/, "Z"), fingerprint_version: 1,
    fingerprint: personFingerprint(salt, words),
  };
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, enc.encode(personStatementBytes(st))));
  return { statement: { statement: st, verkey: personVerkey(key.jwk), signature: lowSSignature(sig) }, salt: b64u(salt) };
}
