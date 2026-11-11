/**
 * What a page that signs a person in to a UTILITY APP checks and holds
 * (`@identity-agent/login-web/app`), ADR-072 section 2.
 *
 * A utility app has no open port: its page is loaded from a fixed address and
 * reaches the app's back end through a relay that is not trusted. So the page
 * does three things a website's page does not, and this module does them once:
 *
 *  - reads the link it was opened from (the app's identifier and key log, the
 *    relay identifier its answers are signed for, the back end's address) and
 *    checks the key log derives that identifier;
 *  - makes a key it cannot export and signs each later request with it;
 *  - believes an answer only if the app signed it, and a challenge only if it
 *    is the app's, for this page's own key, not lapsed.
 *
 * `appFetch` bundles all of that into a `fetch` the SDK's `SignInButton`
 * (`fetchFn`) uses, so the page is the button and this module, and nothing else.
 * It reads no framework and touches only what a browser has.
 */
import {
  blake3Qb64,
  decodeBase64UrlStrict,
  decodeMatterRaw,
  thumbprintP256,
  verifyEd25519,
} from "@identity-agent/login-verify/browser";

const utf8 = new TextEncoder();

function b64uEncode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---- the link ------------------------------------------------------------

export interface AppLink {
  /** The app's identifier. */
  aid: string;
  /** The app's key log, as the link carries it. */
  kel: string;
  /** The relay identifier whose key signs every answer the back end gives. */
  rid: string;
  /** The back end's address. */
  api: string;
}

/** Reads `#aid=…&kel=…&rid=…&api=…`, the fragment a link to the page carries.
 *  A fragment is sent to no server. Throws, saying why, when the link is not
 *  one a page can act on. */
export function readAppLink(hash: string): AppLink {
  const p = new URLSearchParams(hash.replace(/^#/, ""));
  const link = { aid: p.get("aid") ?? "", kel: p.get("kel") ?? "", rid: p.get("rid") ?? "", api: (p.get("api") ?? "").replace(/\/+$/, "") };
  if (!link.aid || !link.kel) throw new Error("the link names no app and key log");
  if (!link.rid) throw new Error("the link names no relay identifier to check the app's answers against");
  if (!/^https:\/\//.test(link.api) && !/^http:\/\/(127\.0\.0\.1|localhost)[:/]/.test(link.api)) {
    throw new Error("the link names no back end to sign in at");
  }
  return link;
}

// ---- the app's key log ---------------------------------------------------

/** Fails unless `aid` is the digest of the inception `text` with d and i
 *  blanked, which is what makes an identifier self-addressing. */
function deriveIdentifier(text: string, aid: string, fail: (why: string) => never): void {
  const blank = "#".repeat(aid.length);
  let dummy = text;
  for (const f of ["d", "i"]) {
    const needle = `"${f}":"${aid}"`;
    if (dummy.split(needle).length !== 2) fail(`its event names ${f} other than once`);
    dummy = dummy.replace(needle, `"${f}":"${blank}"`);
  }
  if (blake3Qb64(utf8.encode(dummy)) !== aid) fail("its inception does not derive the identifier");
}

/** The key the link's key log puts in force for `aid`; throws, saying why, when
 *  it is not one this page reads. */
export async function checkAppKeyLog(aid: string, encoded: string): Promise<Uint8Array> {
  const fail = (why: string): never => {
    throw new Error("the link's key log is refused: " + why);
  };
  if (typeof aid !== "string" || !aid || typeof encoded !== "string" || !encoded) fail("the link names no app key log");
  const json = decodeBase64UrlStrict(encoded);
  if (!json) fail("it is not readable");
  let kl: { raw_events_b64?: string[]; cesr_signatures?: string[] };
  try {
    kl = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(json!));
  } catch {
    return fail("it is not JSON");
  }
  const names = Object.keys(kl ?? {}).sort().join(",");
  if (names !== "cesr_signatures,raw_events_b64") fail("it has fields it should not, or lacks some");
  if (kl.raw_events_b64!.length !== 1 || kl.cesr_signatures!.length !== 1) {
    fail("this page reads an unrotated key log of one event only");
  }
  let raw: Uint8Array;
  try {
    raw = Uint8Array.from(atob(kl.raw_events_b64![0]), (c) => c.charCodeAt(0));
  } catch {
    return fail("its event is not readable");
  }
  let text: string;
  let ev: { t?: string; d?: string; i?: string; kt?: string; k?: string[] };
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    ev = JSON.parse(text);
  } catch {
    return fail("its event is not JSON");
  }
  if (ev.t !== "icp" && ev.t !== "dip") fail("it does not open with an inception");
  if (ev.d !== aid || ev.i !== aid) fail("its inception is not the app's identifier");
  deriveIdentifier(text, aid, fail);
  if (ev.kt !== "1" || !Array.isArray(ev.k) || ev.k.length !== 1) fail("only a single-key identity is read");
  const key = decodeMatterRaw(ev.k![0], "D", 32);
  const sig = decodeMatterRaw(kl.cesr_signatures![0], "0B", 64);
  if (!key || !sig) fail("its key or signature is not spelled one way");
  if (!(await verifyEd25519(sig!, raw, key!))) fail("its inception is not signed by the key it declares");
  return key!;
}

// ---- the challenge -------------------------------------------------------

export interface ChallengeCheck {
  aid: string;
  /** The app's key, from `checkAppKeyLog`. */
  key: Uint8Array;
  /** The exact text the signature covers; read only after the signature holds. */
  body: string;
  sig: string;
  /** The code to show the person. */
  pointer: string;
  /** This page's own browser-key thumbprint. */
  ownThumbprint: string;
  /** The time to judge lapse by (the app's, see `serverSkew`), ms. */
  now?: number;
}

export interface CheckedChallenge {
  session_token: string;
  expiry: string;
  front_end?: string;
}

/** The challenge the signed text says, or an Error: signed by the app's key, for
 *  the app, naming this page's own key and the browser kind, not lapsed, and
 *  with a code that is this challenge's. */
export async function checkAppChallenge(c: ChallengeCheck): Promise<CheckedChallenge> {
  const fail = (why: string): never => {
    throw new Error("the sign-in is refused: " + why);
  };
  const raw = decodeMatterRaw(c.sig, "0B", 64);
  if (typeof c.body !== "string" || !raw) fail("the challenge carries no signature it can read");
  if (!(await verifyEd25519(raw!, utf8.encode(c.body), c.key))) fail("the challenge is not signed by the app");
  let ch: Record<string, unknown>;
  try {
    ch = JSON.parse(c.body);
  } catch {
    return fail("the signed text is not a challenge");
  }
  if (ch.v !== "ASK1" || ch.t !== 1) fail("the signed text is not a login challenge");
  if (ch.site_aid !== c.aid) fail("the challenge is signed for another app");
  if (ch.browser_key !== c.ownThumbprint) fail("the challenge does not name this page's own key");
  // The kind is in the signed body when the Identity Agent names one (ADR-072
  // Amendment 2). A page is a browser; a challenge naming another is not its own.
  if (ch.front_end !== undefined && ch.front_end !== "browser") fail("the challenge is for another kind of front end");
  if (!(Date.parse(String(ch.expiry)) > (c.now ?? Date.now()))) fail("the challenge has lapsed");
  if (typeof ch.session_token !== "string" || !ch.session_token) fail("the challenge names no sign-in");
  let u: URL;
  try {
    u = new URL(c.pointer);
  } catch {
    return fail("the code to open is not an address");
  }
  if (u.protocol !== "https:" || !u.pathname.endsWith("/i/" + ch.session_token)) fail("the code to open is not this challenge's");
  return { session_token: ch.session_token as string, expiry: String(ch.expiry), front_end: ch.front_end as string | undefined };
}

// ---- the app's answers ---------------------------------------------------

export const ANSWER_INCEPTION = "x-keri-app-answer-inception";
export const ANSWER_SIG = "x-keri-app-answer-sig";
const BROWSER_HOST = "browser";

async function sha256hex(bytes: Uint8Array): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource)), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** What the app signed an answer over. */
export async function answerText(rid: string, nonce: string, status: number, contentType: string, body: Uint8Array): Promise<string> {
  return ["APP-ANSWER-V1", rid, BROWSER_HOST, nonce, String(status), contentType, await sha256hex(body)].join("\n");
}

export interface AnswerCheck {
  rid: string;
  nonce: string;
  status: number;
  contentType: string;
  body: Uint8Array;
  inception: string | null;
  sig: string | null;
}

/** Throws unless this answer is the app's: signed with the key of the relay
 *  identifier `rid` the link named, for the call made with `nonce`, carrying
 *  exactly this status, content type and body. */
export async function checkAppAnswer(a: AnswerCheck): Promise<void> {
  const fail = (why: string): never => {
    throw new Error("the answer is not the app's: " + why);
  };
  if (typeof a.rid !== "string" || !a.rid) fail("the link names no relay identifier to check it against");
  const raw = decodeBase64UrlStrict(a.inception ?? "");
  const sigRaw = decodeBase64UrlStrict(a.sig ?? "");
  if (!raw || !raw.length || !sigRaw || !sigRaw.length) fail("it is not signed");
  let text: string;
  let ev: { t?: string; i?: string; d?: string; di?: string; kt?: string; k?: string[] };
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(raw!);
    ev = JSON.parse(text);
  } catch {
    return fail("its inception is unreadable");
  }
  if (ev.t !== "icp" || ev.i !== a.rid || ev.d !== a.rid || ev.di) fail("its inception is not the identifier the link names");
  deriveIdentifier(text, a.rid, fail);
  if (ev.kt !== "1" || !Array.isArray(ev.k) || ev.k.length !== 1) fail("only a single-key identity is read");
  const key = decodeMatterRaw(ev.k![0], "D", 32);
  if (!key) fail("its key is not spelled one way");
  const signed = utf8.encode(await answerText(a.rid, a.nonce, a.status, a.contentType, a.body));
  if (!(await verifyEd25519(sigRaw!, signed, key!))) fail("its signature does not hold for this call");
}

// ---- the browser's key ---------------------------------------------------

export interface BrowserKey {
  privateKey: CryptoKey;
  jwk: { kty: string; crv: string; x: string; y: string };
  /** The RFC 7638 thumbprint, which names this key in a challenge (ADR-066). */
  thumbprint: string;
}

/** RFC 7638 thumbprint of a P-256 public JWK. */
export function browserKeyThumbprint(jwk: { x?: string; y?: string }): string {
  const t = thumbprintP256(jwk.x, jwk.y);
  if (!t) throw new Error("the browser key is not a P-256 key");
  return t;
}

// The key pair lives in IndexedDB as the CryptoKey objects themselves: the
// private key was made non-extractable, so not even this script can read it out.
function db(): Promise<IDBDatabase> {
  return new Promise((res, rej) => {
    const r = indexedDB.open("app-sign-in", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("keys");
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
function idb<T>(mode: IDBTransactionMode, f: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return db().then(
    (d) =>
      new Promise<T>((res, rej) => {
        const t = d.transaction("keys", mode);
        const q = f(t.objectStore("keys"));
        t.oncomplete = () => res(q.result);
        t.onerror = () => rej(t.error);
      }),
  );
}

/** This browser's key for the app `aid`: the one it already holds, else a new
 *  one it cannot export. */
export async function appBrowserKey(aid: string): Promise<BrowserKey> {
  const held = await idb<{ privateKey: CryptoKey; jwk: BrowserKey["jwk"] } | undefined>("readonly", (s) => s.get(aid));
  if (held) return { ...held, thumbprint: browserKeyThumbprint(held.jwk) };
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const j = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const jwk = { kty: j.kty!, crv: j.crv!, x: j.x!, y: j.y! };
  await idb("readwrite", (s) => s.put({ privateKey: pair.privateKey, jwk }, aid));
  return { privateKey: pair.privateKey, jwk, thumbprint: browserKeyThumbprint(jwk) };
}

// ---- proofs --------------------------------------------------------------

/** The string a browser signs to show it holds its key. */
export async function proofText(method: string, target: string, ts: string, nonce: string, binding: string, body = ""): Promise<string> {
  const h = b64uEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8.encode(body))));
  return ["IABK1", method, target, ts, nonce, binding, h].join("\n");
}

/** Headers proving this browser holds its key, for a request to `target` (path
 *  and query as sent) with exactly `body`. `skewMs` is the app's clock less this
 *  one's, so a page on a wrong clock dates its proofs as the app counts. */
export async function proofHeaders(
  privateKey: CryptoKey,
  method: string,
  target: string,
  binding: string,
  body = "",
  skewMs = 0,
): Promise<Record<string, string>> {
  const ts = new Date(Date.now() + skewMs).toISOString().replace(/\.\d{3}Z$/, "Z");
  const nonce = b64uEncode(crypto.getRandomValues(new Uint8Array(16)));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, utf8.encode(await proofText(method, target, ts, nonce, binding, body)));
  return { "X-Browser-Proof-Time": ts, "X-Browser-Proof-Nonce": nonce, "X-Browser-Proof": b64uEncode(new Uint8Array(sig)) };
}

/** The app's clock less this device's, in ms, from the time the app's signed
 *  answer gave; an Error if it gave none. */
export function serverSkew(serverTime: unknown, now = Date.now()): number {
  const t = typeof serverTime === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(serverTime) ? Date.parse(serverTime) : NaN;
  if (Number.isNaN(t)) throw new Error("the app gave no time to go by");
  return t - now;
}

// ---- the fetch the sign-in button uses -----------------------------------

export interface AppFetch {
  /** Pass as `fetchFn` to `SignInButton`, and `sessionEndpoint` below as its
   *  `sessionEndpoint`; `browserKey` is the thumbprint it names in the challenge. */
  fetchFn: typeof fetch;
  sessionEndpoint: string;
  browserKey: string;
  link: AppLink;
}

/** The sign-in button's `fetch` for one app, from the link the page was opened
 *  with. Every call goes to the app's back end with a nonce, and its answer is
 *  read only after it is shown to be the app's for that call. The call that
 *  starts a sign-in also carries this browser's public key and is refused unless
 *  the challenge it returns is the app's, for this key. Every later call carries
 *  a proof made with the key. A refusal is an Error the button shows. */
export async function appFetch(
  link: AppLink,
  opts: { fetchFn?: typeof fetch; browserKey?: (aid: string) => Promise<BrowserKey> } = {},
): Promise<AppFetch> {
  const underlying = opts.fetchFn ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
  const appKey = await checkAppKeyLog(link.aid, link.kel);
  const mine = await (opts.browserKey ?? appBrowserKey)(link.aid);
  const sessionEndpoint = `${link.api}/signin/session`;
  let skew = 0;
  let started: { token: string; expiry: number } | undefined;
  const fetchFn = (async (input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> => {
    const url = String(input);
    const method = (init.method ?? "GET").toUpperCase();
    const isStart = method === "POST" && url === sessionEndpoint;
    let body = init.body as string | undefined;
    const headers: Record<string, string> = { ...(init.headers as Record<string, string> | undefined) };
    if (isStart) body = JSON.stringify({ ...JSON.parse(body ?? "{}"), jwk: mine.jwk });
    if (!isStart && started) {
      if (Date.parse(String(started.expiry)) < Date.now() + skew) throw new Error("the sign-in lapsed; start again");
      Object.assign(headers, await proofHeaders(mine.privateKey, method, new URL(url).pathname + new URL(url).search, started.token, body ?? "", skew));
    }
    const nonce = b64uEncode(crypto.getRandomValues(new Uint8Array(12)));
    headers["X-Browser-Answer-Nonce"] = nonce;
    const r = await underlying(url, { ...init, method, headers, body, cache: "no-store" });
    const bytes = new Uint8Array(await r.arrayBuffer());
    await checkAppAnswer({ rid: link.rid, nonce, status: r.status, contentType: r.headers.get("content-type") ?? "", body: bytes,
      inception: r.headers.get(ANSWER_INCEPTION), sig: r.headers.get(ANSWER_SIG) });
    if (isStart && r.ok) {
      const s = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, string>;
      skew = serverSkew(s.server_time);
      const c = await checkAppChallenge({ aid: link.aid, key: appKey, body: s.canonical_body, sig: s.sig, pointer: s.relay_or_qr_url, ownThumbprint: mine.thumbprint, now: Date.now() + skew });
      // The app's own name for this sign-in is what each later proof is bound to.
      started = { token: s.session_token, expiry: Date.parse(c.expiry) };
    }
    return new Response(bytes, { status: r.status, headers: { "content-type": r.headers.get("content-type") ?? "application/json" } });
  }) as typeof fetch;
  return { fetchFn, sessionEndpoint, browserKey: mine.thumbprint, link };
}

// ---- the signed-in page --------------------------------------------------

/** The app ended the session (or never knew it): the person has to sign in
 *  again. The message is a sentence a person can read and act on. */
export class SessionEnded extends Error {
  constructor() {
    super("Your session with this app has ended, so you have been signed out. Sign in again to carry on.");
    this.name = "SessionEnded";
  }
}

/** One answer from the app, already shown to be the app's. */
export interface AppCall {
  status: number;
  bytes: Uint8Array;
  /** The body read as JSON; `{}` when it has none. */
  json<T = Record<string, unknown>>(): T;
}

export interface AppSession {
  link: AppLink;
  /** The session this browser holds for the app, if it holds one. */
  held(): string | null;
  /** Keeps the session a sign-in handed over. */
  keep(token: string): void;
  /** A call to the app's back end as the person signed in: carries the session
   *  and a proof made with the browser's key, and is believed only if the
   *  app's signed answer holds for it. Throws `SessionEnded` on a 401, after
   *  forgetting the session. */
  call(method: string, path: string, body?: string): Promise<AppCall>;
  /** Who the app says is signed in (`GET /session/whoami`). */
  whoami(): Promise<{ pairwise_aid: string; browser_key: string; server_time: string }>;
  /** Ends the session at the app, as far as the app can be reached, and forgets it here. */
  signOut(): Promise<void>;
  /** The browser's key, for a page that must sign more with it (never exportable). */
  key(): Promise<BrowserKey>;
  /** The app's clock less this device's, ms; known after the first call. */
  skewMs(): number;
}

/** The signed-in half of a utility app's page, from the link it was opened
 *  with: the one place a page makes signed calls, checks each answer is the
 *  app's, keeps its session and ends it. A page has no copy of any of it. */
export function appSession(
  link: AppLink,
  opts: { storage?: Pick<Storage, "getItem" | "setItem" | "removeItem">; fetchFn?: typeof fetch; browserKey?: (aid: string) => Promise<BrowserKey> } = {},
): AppSession {
  const storage = opts.storage ?? sessionStorage;
  const underlying = opts.fetchFn ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
  const slot = "session:" + link.aid;
  let skew = 0;
  let synced = false;
  let mine: Promise<BrowserKey> | undefined;
  const key = () => (mine ??= (opts.browserKey ?? appBrowserKey)(link.aid));
  const sha256b64u = async (t: string) => b64uEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8.encode(t))));

  async function raw(method: string, path: string, body: string): Promise<AppCall> {
    const token = storage.getItem(slot);
    if (!token) throw new SessionEnded();
    const k = await key();
    const nonce = b64uEncode(crypto.getRandomValues(new Uint8Array(12)));
    const proof = await proofHeaders(k.privateKey, method, path, await sha256b64u(token), body, skew);
    const headers: Record<string, string> = { Authorization: "Bearer " + token, "X-Browser-Answer-Nonce": nonce, ...proof };
    if (method !== "GET") headers["Content-Type"] = "application/json";
    const r = await underlying(link.api + path, { method, cache: "no-store", headers, ...(method === "GET" ? {} : { body }) });
    const bytes = new Uint8Array(await r.arrayBuffer());
    await checkAppAnswer({ rid: link.rid, nonce, status: r.status, contentType: r.headers.get("content-type") ?? "", body: bytes,
      inception: r.headers.get(ANSWER_INCEPTION), sig: r.headers.get(ANSWER_SIG) });
    if (r.status === 401) {
      storage.removeItem(slot);
      throw new SessionEnded();
    }
    return { status: r.status, bytes, json: <T,>() => JSON.parse(new TextDecoder().decode(bytes) || "{}") as T };
  }

  const session: AppSession = {
    link,
    held: () => storage.getItem(slot),
    keep: (token) => storage.setItem(slot, token),
    key,
    skewMs: () => skew,
    async whoami() {
      const r = await raw("GET", "/session/whoami", "");
      if (r.status !== 200) throw new Error("The app would not say who is signed in.");
      const w = r.json<{ pairwise_aid: string; browser_key: string; server_time: string }>();
      skew = serverSkew(w.server_time);
      synced = true;
      return w;
    },
    async call(method, path, body = "") {
      // A reload has lost the app's clock: ask for it first, so the proof is dated as the app counts.
      if (!synced) await session.whoami();
      return raw(method.toUpperCase(), path, body);
    },
    async signOut() {
      try {
        if (storage.getItem(slot)) await session.call("POST", "/session/signout", "{}");
      } catch {
        // The app could not be reached or had already ended it: either way this browser forgets it.
      } finally {
        storage.removeItem(slot);
      }
    },
  };
  return session;
}

export { signInProblem } from "./signInProblem.js";
