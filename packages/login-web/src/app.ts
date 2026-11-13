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
import { deriveIdentifier, logExtends, readAnswerLog } from "./keylog.js";
export { logExtends };
import type { CheckedLog, LogEvent } from "./keylog.js";
export type { CheckedLog, LogEvent };
import { askWitnesses, judgeLinkLog } from "./witnessed.js";
import { isSealingKeyAnswer, SEAL_PATH, SEAL_STATEMENT_PATH, SealError, sealKeyStatementText, sealRequest, unb64u } from "./seal.js";
import {
  blake3Qb64,
  decodeBase64UrlStrict,
  decodeMatterRaw,
  thumbprintP256,
  verifyEd25519,
} from "@identity-agent/login-verify/browser";

const utf8 = new TextEncoder();

function lowerCase(h: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(h).map(([k, v]) => [k.toLowerCase(), v]));
}

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
  /** The back end's sealing key, vouched for by the relay identifier (`checkSealKey`). */
  seal: string;
  /** The latest event of the relay identifier's key log the owner's Identity Agent has
   *  seen, as `<sequence number>.<SAID>`: a log the page is shown must hold that event at
   *  that number (`checkSealKey`), so a page that has seen nothing before is not handed an
   *  earlier log. */
  min: string;
  /** Where to ask the relay identifier's witnesses for its key log, each the address a witness's
   *  routes are under (`<address>/witness/kel/<rid>`), as the owner's Identity Agent wrote them. Empty
   *  when the identifier has none. Nothing vouches for an address: what a witness answers is checked
   *  against the identifier's own inception (`readWitnessedLog`), and an address that is wrong is only
   *  a witness that cannot be reached. */
  wit: string[];
}

/** The most witnesses a link names. */
export const MAX_LINK_WITNESSES = 8;

/** `<sequence number>.<SAID>`, or null when `min` is not that. */
export function readMinimum(min: unknown): { sn: number; said: string } | null {
  const m = typeof min === "string" ? /^(0|[1-9][0-9]{0,2})\.([A-Za-z0-9_-]{20,100})$/.exec(min) : null;
  return m ? { sn: Number(m[1]), said: m[2] } : null;
}

/** The witness addresses a link's `wit` names, comma separated; throws unless each is an https address (or a local one), none is
 *  named twice, and there are no more than `MAX_LINK_WITNESSES`. No `wit` is no addresses. */
function readWitnessAddresses(text: string | null): string[] {
  if (text === null || text === "") return [];
  const list = text.split(",").map((a) => a.replace(/\/+$/, ""));
  if (list.length > MAX_LINK_WITNESSES || list.some((a) => !/^https:\/\/[^\s,]+$/.test(a) && !/^http:\/\/(127\.0\.0\.1|localhost)[:/][^\s,]*$/.test(a)) || new Set(list).size !== list.length) {
    throw new Error("the link names a witness address that is not one this page asks");
  }
  return list;
}

/** How long after it was made a sign-in link is still taken, in seconds. A link carries `iat`, the
 *  time the owner's Identity Agent made it (whole seconds since 1970): a link is made each time the
 *  owner asks for one, so a link older than this is one nobody has just been given. It bounds how
 *  stale the key log inside it may be. */
export const LINK_MAX_AGE_SECONDS = 7 * 24 * 60 * 60;
/** How far ahead of this device's clock a link may be dated, in seconds, before the clock is blamed. */
export const LINK_MAX_AHEAD_SECONDS = 24 * 60 * 60;

/** Reads `#aid=…&kel=…&rid=…&api=…&seal=…&min=…&iat=…`, the fragment a link to the page carries.
 *  A fragment is sent to no server. Throws, saying why, when the link is not
 *  one a page can act on, or was made longer ago than `LINK_MAX_AGE_SECONDS` (as of `now`, ms). */
export function readAppLink(hash: string, now = Date.now()): AppLink {
  const p = new URLSearchParams(hash.replace(/^#/, ""));
  const link = { aid: p.get("aid") ?? "", kel: p.get("kel") ?? "", rid: p.get("rid") ?? "", api: (p.get("api") ?? "").replace(/\/+$/, ""), seal: p.get("seal") ?? "", min: p.get("min") ?? "" };
  if (!link.aid || !link.kel) throw new Error("the link names no utility app and key log");
  if (!link.rid) throw new Error("the link names no relay identifier to check the utility app's answers against");
  if (!link.seal) throw new Error("the link names no sealing key to seal calls to the utility app with");
  const wit = readWitnessAddresses(p.get("wit"));
  if (!readMinimum(link.min)) throw new Error("the link names no latest key log event the utility app's relay identifier must have reached");
  if (!/^https:\/\//.test(link.api) && !/^http:\/\/(127\.0\.0\.1|localhost)[:/]/.test(link.api)) {
    throw new Error("the link names no back end to sign in at");
  }
  const iat = /^[1-9][0-9]{9,10}$/.test(p.get("iat") ?? "") ? Number(p.get("iat")) : null;
  if (iat === null) throw new Error("the link names no time it was made");
  const age = now / 1000 - iat;
  if (age > LINK_MAX_AGE_SECONDS) throw new Error("this link was made more than 7 days ago and is no longer taken: ask the utility app's owner for a new one");
  if (age < -LINK_MAX_AHEAD_SECONDS) throw new Error("this link is dated later than this device's clock says it is now: set the date and time on this device, or ask the utility app's owner for a new link");
  return { ...link, wit };
}

// ---- the app's key log ---------------------------------------------------

/** The key the link's key log puts in force for `aid`; throws, saying why, when
 *  it is not one this page reads. */
export async function checkAppKeyLog(aid: string, encoded: string): Promise<Uint8Array> {
  const fail = (why: string): never => {
    throw new Error("the link's key log is refused: " + why);
  };
  if (typeof aid !== "string" || !aid || typeof encoded !== "string" || !encoded) fail("the link names no utility app key log");
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
  if (ev.d !== aid || ev.i !== aid) fail("its inception is not the utility app's identifier");
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
  if (!(await verifyEd25519(raw!, utf8.encode(c.body), c.key))) fail("the challenge is not signed by the utility app");
  let ch: Record<string, unknown>;
  try {
    ch = JSON.parse(c.body);
  } catch {
    return fail("the signed text is not a challenge");
  }
  if (ch.v !== "ASK1" || ch.t !== 1) fail("the signed text is not a login challenge");
  if (ch.site_aid !== c.aid) fail("the challenge is signed for another utility app");
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

export const ANSWER_LOG = "x-keri-app-answer-log";
export const ANSWER_SIG = "x-keri-app-answer-sig";
const BROWSER_HOST = "browser";

async function sha256hex(bytes: Uint8Array): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource)), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** What the app signed an answer over. */
export async function answerText(rid: string, nonce: string, status: number, contentType: string, body: Uint8Array): Promise<string> {
  return ["APP-ANSWER-V1", rid, BROWSER_HOST, nonce, String(status), contentType, await sha256hex(body)].join("\n");
}

// ---- the relay identifier's key log --------------------------------------

/** The key the relay identifier `rid`'s key log (`encoded`, base64url, as the
 *  X-Keri-App-Answer-Log header carries it) names now; throws, saying why,
 *  when it is not the identifier's own valid log. */
export async function checkAnswerKeyLog(rid: string, encoded: string): Promise<CheckedLog> {
  return readAnswerLog(rid, encoded, (why: string): never => {
    throw new Error("the answer's key log is refused: " + why);
  });
}

/** What a page remembers of an app's key log between answers, per relay
 *  identifier: the longest it has been shown. Without it a key the log has since
 *  left would be believed again by showing its own shorter log. */
export interface LogMemory {
  get(rid: string): string | null;
  set(rid: string, log: string): void;
}

const memoryOnly = new Map<string, string>();

/** The page's memory: this browser's local storage, and in the page alone when
 *  there is none (a private window, a test). */
export function browserLogMemory(): LogMemory {
  const slot = (rid: string) => "app-answer-log:" + rid;
  const store = (): Pick<Storage, "getItem" | "setItem"> | undefined => {
    try {
      return typeof localStorage === "undefined" ? undefined : localStorage;
    } catch {
      return undefined;
    }
  };
  return {
    get(rid) {
      try {
        return store()?.getItem(slot(rid)) ?? memoryOnly.get(rid) ?? null;
      } catch {
        return memoryOnly.get(rid) ?? null;
      }
    },
    set(rid, log) {
      memoryOnly.set(rid, log);
      try {
        store()?.setItem(slot(rid), log);
      } catch {
        // The page's own copy still holds for this load.
      }
    },
  };
}

export interface AnswerCheck {
  rid: string;
  nonce: string;
  status: number;
  contentType: string;
  body: Uint8Array;
  /** The X-Keri-App-Answer-Log header: the identifier's signed key log. */
  log: string | null;
  /** The longest log this page already holds for `rid` (`LogMemory`), if any. */
  known?: string | null;
  sig: string | null;
}

/** The log to remember once `got` (read from `text`) has been shown: the longer of it and
 *  `known`, the longest this page already holds for `rid`. Refuses (through `fail`) a log
 *  that does not carry on from the one held, which is how a key the log has since left is
 *  kept from being believed again. The one rule for an answer and a sealing key alike. */
async function holdLog(rid: string, got: CheckedLog, text: string, known: string | null | undefined, fail: (why: string) => never, floored = false): Promise<string> {
  if (!known) return text;
  let held: CheckedLog | undefined;
  try {
    held = await readAnswerLog(rid, known, (why): never => {
      throw new Error(why);
    });
  } catch {
    // What was kept is unreadable. Where the link gave a minimum (`floored`) the log shown
    // is held to that, and replaces it; with none, refusing is the only way not to take the
    // first log offered as if this page had never seen one.
    if (floored) return text;
    return fail("what this page kept of the utility app's key log cannot be read, and the link gives nothing to hold the log to");
  }
  if (!logExtends(got.events, held.events)) fail("its key log is behind or apart from the one this page already knows for the utility app: the key that signed it may have been rotated away");
  return held.events.length === got.events.length ? known : text;
}

/** Throws unless this answer is the app's: signed with the CURRENT key of the
 *  relay identifier `rid` the link named, as its key log names it, a log that
 *  carries on from the longest one this page already holds; for the call made
 *  with `nonce`, carrying exactly this status, content type and body. Gives the
 *  log to remember: the longer of the two. */
export async function checkAppAnswer(a: AnswerCheck): Promise<{ log: string }> {
  const fail = (why: string): never => {
    throw new Error("the answer is not the utility app's: " + why);
  };
  if (typeof a.rid !== "string" || !a.rid) fail("the link names no relay identifier to check it against");
  const sigRaw = decodeBase64UrlStrict(a.sig ?? "");
  if (!sigRaw || !sigRaw.length) fail("it is not signed");
  const got = await readAnswerLog(a.rid, a.log, fail);
  const keep = await holdLog(a.rid, got, a.log as string, a.known, fail);
  const signed = utf8.encode(await answerText(a.rid, a.nonce, a.status, a.contentType, a.body));
  if (!(await verifyEd25519(sigRaw!, signed, got.key))) fail("its signature does not hold for this call");
  return { log: keep };
}

// ---- sealed traffic ------------------------------------------------------

/** The back end's sealing key the link carries, 65 bytes, with the relay identifier's key
 *  log to remember, or an Error saying why not. The statement is the identifier's whole
 *  signed key log, the key, the log's last sequence number `sn`, and a signature over
 *  `sealKeyStatementText(rid, key, sn)`. It is read as an answer's log is: the log is the
 *  identifier `rid`'s own, from its inception, and carries on from the longest this page
 *  already holds (`known`); and the signature is the key that log names NOW, at its last
 *  event. So a key the identifier has rotated away from vouches for nothing, and a
 *  statement made at an earlier event is not taken for a later one. `min` is the link's
 *  latest event the Identity Agent has seen (`readMinimum`): the log must hold it, at that
 *  sequence number, so a page with no memory still takes no log shorter than it. */
export async function checkSealKey(rid: string, encoded: string, known?: string | null, min?: string | null): Promise<{ key: Uint8Array; log: string }> {
  const fail = (why: string): never => {
    throw new Error("the link's sealing key is refused: " + why);
  };
  const json = decodeBase64UrlStrict(typeof encoded === "string" ? encoded : "");
  if (!json) fail("it is not readable");
  let st: { log?: unknown; key?: unknown; sn?: unknown; sig?: unknown };
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(json!);
    st = JSON.parse(text);
  } catch {
    return fail("it is not JSON");
  }
  if (Object.keys(st ?? {}).sort().join(",") !== "key,log,sig,sn") fail("it has fields it should not, or lacks some");
  const key = unb64u(st.key);
  const sig = unb64u(st.sig);
  if (typeof st.log !== "string" || !key || !sig) fail("a part of it is not spelled one way");
  // The text must be the one the SDK writes: the four fields in this order, with no space and no
  // escape, and the sequence number a whole number written as one. JSON.parse reads 0.0 and 1e0 as
  // the integers 0 and 1, an escaped field name as its plain one, and the last of two of one name,
  // so the text itself is held to the one spelling, as Go and Dart do.
  if (typeof st.sn !== "number" || text !== JSON.stringify({ log: st.log, key: st.key, sn: st.sn, sig: st.sig })) fail("it is not written the one way a statement is");
  if (key!.length !== 65 || key![0] !== 4) fail("the key is not an uncompressed P-256 point");
  const got = await readAnswerLog(rid, st.log as string, (why): never => fail("its key log is refused: " + why));
  if (st.sn !== got.events.length - 1) fail("it is made at a sequence number other than its key log's last");
  const floor = min == null ? null : readMinimum(min);
  if (min != null && !floor) fail("the link's latest key log event is not spelled one way");
  if (floor && got.events[floor.sn]?.said !== floor.said) fail("its key log does not reach the latest event your Identity Agent has seen for the utility app's relay identifier: it may be an earlier log, from before a key was rotated away");
  const keep = await holdLog(rid, got, st.log as string, known, fail, !!floor);
  if (!(await verifyEd25519(sig!, sealKeyStatementText(rid, key!, st.sn as number), got.key))) fail("the relay identifier's current key did not sign this key");
  return { key: key!, log: keep };
}

/** The link's sealing key, checked against the log this page holds, which is then the longer. Where the relay
 *  identifier names witnesses (and the link says where to ask them) the page also asks them for the log
 *  (`askWitnesses`), because what a link carries is only as new as the link: a log the witnesses vouch for that
 *  goes on past the link's means the key the link vouched the sealing key for has been rotated away, and that is
 *  refused, with the witnessed log kept so that a stale link stays refused. A log that carries on from what the
 *  witnesses vouch for (they may not have been told yet, a removal does not wait for them) is taken as before,
 *  held to the link's minimum. Witnesses that cannot be reached, or have receipted nothing, change nothing. */
export async function checkedSealKey(link: Pick<AppLink, "rid" | "seal" | "min"> & { wit?: string[] }, logs: LogMemory, ask: typeof fetch, statement: string = link.seal): Promise<{ key: Uint8Array; log: string }> {
  const r = await checkSealKey(link.rid, statement, logs.get(link.rid), link.min);
  if (link.wit?.length) {
    const mine = await readAnswerLog(link.rid, r.log, (why): never => {
      throw new Error(why);
    });
    const j = await judgeLinkLog(link.rid, r.log, await askWitnesses(link.rid, mine.inception, link.wit, ask));
    if (j.verdict === "refused") throw new Error("the link's sealing key is refused: the witnesses of the utility app's relay identifier hold a key log that cannot be right (two histories each receipted, or a rotation that cut every witness)");
    if (j.verdict === "moved_on" || j.verdict === "apart") {
      if (j.verdict === "moved_on") logs.set(link.rid, j.log as string);
      throw new Error(
        j.verdict === "moved_on"
          ? "the link's sealing key is refused: the utility app's relay identifier has moved on since this link was made, as its witnesses show: ask the utility app's owner for a new link"
          : "the link's sealing key is refused: the utility app's relay identifier has a different key log at the witnesses than the link carries",
      );
    }
  }
  logs.set(link.rid, r.log);
  return r;
}

/** A call was sealed to a sealing key that is not the one in force, and the back end said so
 *  (`isSealingKeyAnswer`). Nothing was believed or refused yet: `renewedSealKey` fetches the statement now in
 *  force and the call is sealed again. */
export class SealingKeyMoved extends Error {
  constructor() {
    super("The utility app's sealing key has moved on.");
    this.name = "SealingKeyMoved";
  }
}

/** The link this page was opened with names a sealing key that is out of date and the page could not get the
 *  one now in force: the person is to open the utility app again. */
export class LinkOutOfDate extends Error {
  constructor() {
    super("This link is out of date. Open this utility app again from your Identity Agent.");
    this.name = "LinkOutOfDate";
  }
}

/** The sealing key now in force, got after a call did not open (a rotation moved it): the statement
 *  is fetched from the back end's own address (`SEAL_STATEMENT_PATH`, the one a new link would carry) and checked
 *  as a link's is, held to the link's `min` and to the longest log this page already knows, so it must carry on
 *  from both and be signed by the relay identifier's current key; the witnesses a link names are asked as
 *  for a link. `held` is the key the failed call was sealed to. A statement that fails a check is `LinkOutOfDate`; a
 *  statement that cannot be fetched is the relay failing (`AppUnreachable`); one that names the key already held
 *  is not a rotation, so it is `AppUnreachable` too (trying again can still work). */
export async function renewedSealKey(link: Pick<AppLink, "rid" | "api" | "min"> & { wit?: string[] }, logs: LogMemory, ask: typeof fetch, held: Uint8Array): Promise<{ key: Uint8Array; log: string }> {
  let r: Response;
  let text: string;
  try {
    r = await ask(link.api + SEAL_STATEMENT_PATH, { method: "GET", cache: "no-store" });
    text = await r.text();
  } catch {
    throw new AppUnreachable(0);
  }
  if (r.status !== 200) throw new AppUnreachable(r.status);
  let now: { key: Uint8Array; log: string };
  try {
    now = await checkedSealKey({ ...link, seal: text }, logs, ask, text);
  } catch {
    throw new LinkOutOfDate();
  }
  if (now.key.length === held.length && now.key.every((b, i) => b === held[i])) throw new AppUnreachable(r.status);
  return now;
}

/** `sealedCall`, and when the back end says the key it was sealed to has moved on, once the key now in force
 *  (`renewedSealKey`) and the same call sealed to that; a second such answer is `LinkOutOfDate`. The call's text is
 *  not touched, so what a person was sending is sent. `renew` is given the key that failed and keeps what it returns. */
async function sealedCallRenewing(
  link: Pick<AppLink, "rid" | "api">,
  key: () => Promise<Uint8Array>,
  renew: (held: Uint8Array) => Promise<Uint8Array>,
  call: SealedCall,
  nonce: string,
  underlying: typeof fetch,
  logs: LogMemory,
  now: number,
): Promise<SealedAnswer> {
  const held = await key();
  try {
    return await sealedCall(link, held, call, nonce, underlying, logs, now);
  } catch (e) {
    if (!(e instanceof SealingKeyMoved)) throw e;
  }
  const fresh = await renew(held);
  try {
    return await sealedCall(link, fresh, call, nonce, underlying, logs, now);
  } catch (e) {
    throw e instanceof SealingKeyMoved ? new LinkOutOfDate() : e;
  }
}

/** The relay that carries a call to the app's back end did not carry it (it answered with
 *  something other than the one sealed answer), as in a restart. Nothing was believed or
 *  refused: the call can be made again. Not a refusal to trust. */
export class AppUnreachable extends Error {
  constructor(public readonly status: number) {
    super(`The utility app could not be reached just now. Try again in a moment.`);
    this.name = "AppUnreachable";
  }
}

/** The answer the back end signs to a call that opened but was dated by a clock the
 *  back end does not share: 409, `{"error":"clock","server_time":…}` (ADR-072 Amendment 4; login-go's
 *  `ClockAnswer`, the `clock_answer` case in seal.json).
 *  Gives the back end's clock less this device's, in ms, or null when the answer is
 *  not that. It is read only from an answer `sealedCall` has already shown to be the app's. */
export function clockAnswerSkew(r: SealedAnswer, now = Date.now()): number | null {
  if (r.status !== 409) return null;
  try {
    const j = JSON.parse(new TextDecoder().decode(r.bytes)) as { error?: unknown; server_time?: unknown };
    return j && j.error === "clock" ? serverSkew(j.server_time, now) : null;
  } catch {
    return null;
  }
}

export interface SealedCall {
  method: string;
  /** Path and query, as the back end's routes see them. */
  target: string;
  headers: Record<string, string>;
  body: string;
}

export interface SealedAnswer {
  status: number;
  contentType: string;
  bytes: Uint8Array;
}

/** Makes a call to the back end that the relay reads none of: one fixed POST
 *  whose body is the call sealed for the back end, and whose answer is read
 *  only once opened and shown to be the app's for this call (`checkAppAnswer`).
 *  The proof and session headers are part of what is sealed. A refusal to open
 *  or to believe is an Error; the relay's own failure is an Error that says so. */
export async function sealedCall(
  link: Pick<AppLink, "rid" | "api">,
  sealKey: Uint8Array,
  call: SealedCall,
  nonce: string,
  underlying: typeof fetch,
  logs: LogMemory,
  now = Date.now(),
): Promise<SealedAnswer> {
  const content = utf8.encode(JSON.stringify({
    method: call.method,
    target: call.target,
    headers: { ...call.headers, "x-browser-answer-nonce": nonce },
    body: call.body,
    ts: new Date(now).toISOString().replace(/\.\d{3}Z$/, "Z"),
  }));
  const { outer, reply } = await sealRequest(link.rid, sealKey, content);
  const r = await underlying(link.api + SEAL_PATH, { method: "POST", cache: "no-store", headers: { "content-type": "application/json" }, body: outer });
  const text = await r.text();
  // The relay is only the road: it failing (a restart, a busy moment) is not the
  // answer being wrong, so the person is told to try again, not warned off.
  if (isSealingKeyAnswer(r.status, text)) throw new SealingKeyMoved();
  if (r.status !== 200) throw new AppUnreachable(r.status);
  let inner: { status?: unknown; content_type?: unknown; body?: unknown; log?: unknown; sig?: unknown };
  try {
    inner = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await reply.open(text)));
  } catch (e) {
    throw e instanceof SealError ? new Error("the answer is not the utility app's: it does not open") : new Error("the answer is not the utility app's: it is not readable");
  }
  const bytes = unb64u(inner?.body);
  if (!Number.isInteger(inner?.status) || typeof inner?.content_type !== "string" || !bytes) throw new Error("the answer is not the utility app's: it is not readable");
  logs.set(link.rid, (await checkAppAnswer({ rid: link.rid, nonce, status: inner.status as number, contentType: inner.content_type as string, body: bytes,
    log: typeof inner.log === "string" ? inner.log : null, known: logs.get(link.rid), sig: typeof inner.sig === "string" ? inner.sig : null })).log);
  return { status: inner.status as number, contentType: inner.content_type as string, bytes };
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

/** What this browser keeps a link's session and key under: the app, the relay
 *  that carries its calls and the address they go to, all three. A link that
 *  names the same app with another relay or address is another place, so a
 *  crafted one never reaches what was kept for the real one. */
export function linkSlot(link: Pick<AppLink, "aid" | "rid" | "api">): string {
  return JSON.stringify([link.aid, link.rid, link.api]);
}

/** This browser's key for a link (`linkSlot`): the one it already holds, else a
 *  new one it cannot export. */
export async function appBrowserKey(slot: string): Promise<BrowserKey> {
  const held = await idb<{ privateKey: CryptoKey; jwk: BrowserKey["jwk"] } | undefined>("readonly", (s) => s.get(slot));
  if (held) return { ...held, thumbprint: browserKeyThumbprint(held.jwk) };
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const j = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const jwk = { kty: j.kty!, crv: j.crv!, x: j.x!, y: j.y! };
  await idb("readwrite", (s) => s.put({ privateKey: pair.privateKey, jwk }, slot));
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
  if (Number.isNaN(t)) throw new Error("the utility app gave no time to go by");
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
  opts: { fetchFn?: typeof fetch; browserKey?: (slot: string) => Promise<BrowserKey>; logs?: LogMemory; witnessFetch?: typeof fetch } = {},
): Promise<AppFetch> {
  const logs = opts.logs ?? browserLogMemory();
  const underlying = opts.fetchFn ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
  const appKey = await checkAppKeyLog(link.aid, link.kel);
  let sealKey = (await checkedSealKey(link, logs, opts.witnessFetch ?? underlying)).key;
  const mine = await (opts.browserKey ?? appBrowserKey)(linkSlot(link));
  const sessionEndpoint = `${link.api}/signin/session`;
  let skew = 0;
  let started: { token: string; expiry: number } | undefined;
  const fetchFn = (async (input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> => {
    const url = String(input);
    const method = (init.method ?? "GET").toUpperCase();
    const isStart = method === "POST" && url === sessionEndpoint;
    let body = init.body as string | undefined;
    if (isStart) body = JSON.stringify({ ...JSON.parse(body ?? "{}"), jwk: mine.jwk });
    const u = new URL(url);
    if (url !== link.api && !url.startsWith(link.api + "/")) throw new Error("this page speaks only to its own utility app's back end");
    // A device whose clock is off by more than the back end takes is told the time
    // in a signed answer, and dates the call by it, once.
    let r: SealedAnswer;
    for (let again = false; ; again = true) {
      const headers: Record<string, string> = { ...(init.headers as Record<string, string> | undefined) };
      if (!isStart && started) {
        if (Date.parse(String(started.expiry)) < Date.now() + skew) throw new Error("the sign-in lapsed; start again");
        Object.assign(headers, await proofHeaders(mine.privateKey, method, new URL(url).pathname + new URL(url).search, started.token, body ?? "", skew));
      }
      const nonce = b64uEncode(crypto.getRandomValues(new Uint8Array(12)));
      r = await sealedCallRenewing(link, async () => sealKey, async (held) => (sealKey = (await renewedSealKey(link, logs, opts.witnessFetch ?? underlying, held)).key),
        { method, target: u.pathname + u.search, headers: lowerCase(headers), body: body ?? "" }, nonce, underlying, logs, Date.now() + skew);
      const off = clockAnswerSkew(r);
      if (off === null) break;
      if (again) throw new Error("This device's clock is too far from the utility app's to sign in. Set the date and time on this device, then try again.");
      skew = off;
    }
    const bytes = r.bytes;
    if (isStart && r.status >= 200 && r.status < 300) {
      const s = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, string>;
      skew = serverSkew(s.server_time);
      const c = await checkAppChallenge({ aid: link.aid, key: appKey, body: s.canonical_body, sig: s.sig, pointer: s.relay_or_qr_url, ownThumbprint: mine.thumbprint, now: Date.now() + skew });
      // The app's own name for this sign-in is what each later proof is bound to.
      started = { token: s.session_token, expiry: Date.parse(c.expiry) };
    }
    return new Response(bytes as BufferSource, { status: r.status, headers: { "content-type": r.contentType || "application/json" } });
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
  opts: { storage?: Pick<Storage, "getItem" | "setItem" | "removeItem">; fetchFn?: typeof fetch; browserKey?: (slot: string) => Promise<BrowserKey>; logs?: LogMemory; witnessFetch?: typeof fetch } = {},
): AppSession {
  const logs = opts.logs ?? browserLogMemory();
  const storage = opts.storage ?? sessionStorage;
  const underlying = opts.fetchFn ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
  const slot = "session:" + linkSlot(link);
  let sealKey: Promise<{ key: Uint8Array; log: string }> | undefined;
  let skew = 0;
  let synced = false;
  let mine: Promise<BrowserKey> | undefined;
  const key = () => (mine ??= (opts.browserKey ?? appBrowserKey)(linkSlot(link)));
  const sha256b64u = async (t: string) => b64uEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8.encode(t))));

  async function raw(method: string, path: string, body: string): Promise<AppCall> {
    const token = storage.getItem(slot);
    if (!token) throw new SessionEnded();
    const k = await key();
    let r: SealedAnswer;
    for (let again = false; ; again = true) {
      const nonce = b64uEncode(crypto.getRandomValues(new Uint8Array(12)));
      const proof = await proofHeaders(k.privateKey, method, path, await sha256b64u(token), body, skew);
      const headers: Record<string, string> = lowerCase({ Authorization: "Bearer " + token, ...proof });
      if (method !== "GET") headers["content-type"] = "application/json";
      r = await sealedCallRenewing(link, async () => (await (sealKey ??= checkedSealKey(link, logs, opts.witnessFetch ?? underlying))).key,
        async (held) => {
          const fresh = await renewedSealKey(link, logs, opts.witnessFetch ?? underlying, held);
          sealKey = Promise.resolve(fresh);
          return fresh.key;
        },
        { method, target: path, headers, body: method === "GET" ? "" : body }, nonce, underlying, logs, Date.now() + skew);
      const off = clockAnswerSkew(r);
      if (off === null) break;
      if (again) throw new Error("This device's clock is too far from the utility app's. Set the date and time on this device, then try again.");
      skew = off;
    }
    const bytes = r.bytes;
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
      if (r.status !== 200) throw new Error("The utility app would not say who is signed in.");
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
