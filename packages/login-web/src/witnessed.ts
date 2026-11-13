/**
 * A relay identifier's key log as its witnesses hold it, ADR-072 Amendment 5.
 *
 * A utility app's relay identifier names witnesses in its inception, and a page can ask them
 * for the log (GET /witness/kel/{rid}, presenting the inception in X-Inception-Event). Each
 * witness answers with the events it holds, each with its bytes, the controller's signature
 * and this witness's own receipt. Nothing a witness says is believed: this module reads every
 * answer as a key log (`readAnswerLog`, as an answer's log is read), pools the receipts, and
 * counts for each event the distinct witnesses the identifier designated at that event whose
 * signature over the event's bytes verifies, against the threshold (`bt`) in force. A log is
 * taken as far as every event has its threshold, and no further.
 *
 * The rules are the core's (`drivers.WitnessingByEvent`): the witness list is carried forward
 * through the log (an inception names it, a rotation cuts `br` then adds `ba`); a receipt's
 * index is the witness's place in that list; a witness counts once, by its key. They are held
 * to the cases in `test-vectors/seal.json` (`witnessed`), which the core runs through its own
 * code, this module through its own, and login-dart through its.
 */
import { decodeMatterRaw, verifyEd25519 } from "@identity-agent/login-verify/browser";
import { MAX_LOG_EVENTS, logExtends, readAnswerLog } from "./keylog.js";
import type { CheckedLog } from "./keylog.js";
import { b64u } from "./seal.js";

const utf8 = new TextEncoder();

/** One entry of a witness's answer, as it is served. */
export interface WitnessedEvent {
  raw_bytes_b64?: unknown;
  cesr_signature?: unknown;
  witness_receipts?: unknown;
}

/** A witness's answer to GET /witness/kel/{rid}. */
export interface WitnessAnswer {
  aid?: unknown;
  kel?: unknown;
}

export interface WitnessedLog {
  /** The log as the page reads it (a CESR stream, base64url), cut after the last event that has its threshold of receipts. */
  log: string;
  /** How many events it holds. */
  events: number;
  checked: CheckedLog;
}

function strictBase64(s: unknown): Uint8Array | null {
  if (typeof s !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) return null;
  try {
    const out = Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
    return btoa(String.fromCharCode(...out)) === s ? out : null;
  } catch {
    return null;
  }
}

type Ev = { t?: string; d?: string; bt?: unknown; b?: unknown; br?: unknown; ba?: unknown };

const strings = (v: unknown): string[] | null => (Array.isArray(v) && v.every((x) => typeof x === "string") ? (v as string[]) : null);

/** The witnesses in force after `ev` (the core's `WitnessesAfter`), or null when `ev` does not say. */
function witnessesAfter(current: string[], ev: Ev): string[] | null {
  if (ev.t === "icp") return strings(ev.b);
  if (ev.t !== "rot") return current;
  const cut = strings(ev.br);
  const add = strings(ev.ba);
  if (!cut || !add) return null;
  const out = current.filter((w) => !cut.includes(w));
  for (const w of add) if (!out.includes(w)) out.push(w);
  return out;
}

/** The threshold an establishment event sets: `bt`, a number written in hex, as the core reads it. */
function toadOf(ev: Ev): number | null {
  return typeof ev.bt === "string" && /^(0|[1-9a-f][0-9a-f]{0,3})$/.test(ev.bt) ? parseInt(ev.bt, 16) : null;
}

/** How many leading events of `texts` have their threshold of receipts (an unwitnessed event
 *  has threshold 0 and is always met). `receipts` are by event SAID. Fails closed: an event whose
 *  witnesses or threshold cannot be read ends the count. */
async function receiptedThrough(texts: string[], receipts: Map<string, { witness: string; sig: string }[]>): Promise<number> {
  let designated: string[] = [];
  let toad = 0;
  for (let i = 0; i < texts.length; i++) {
    let ev: Ev;
    try {
      ev = JSON.parse(texts[i]);
    } catch {
      return i;
    }
    const after = witnessesAfter(designated, ev);
    const bt = toadOf(ev);
    if (!after || bt === null) return i;
    designated = after;
    toad = bt;
    const keys = new Set<string>();
    for (const r of receipts.get(ev.d as string) ?? []) {
      const at = designated.indexOf(r.witness);
      const key = decodeMatterRaw(r.witness, "B", 32);
      if (at < 0 || !key || r.sig.length !== 88 || r.sig[0] !== "A") continue;
      const idx = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".indexOf(r.sig[1]);
      if (idx !== at) continue;
      const raw = decodeMatterRaw(r.sig, r.sig.slice(0, 2), 64);
      if (!raw || !(await verifyEd25519(raw, utf8.encode(texts[i]), key))) continue;
      keys.add(r.witness);
    }
    if (keys.size < toad) return i;
  }
  return texts.length;
}

/** Reads the answers of the witnesses a relay identifier names (each to GET /witness/kel/{rid})
 *  into the log they together vouch for: the longest log whose every event has its threshold of
 *  receipts from the witnesses the identifier designated. Throws, saying why, when there is none,
 *  or when two logs that both reach a place disagree on an event before it (a fork the witnesses
 *  receipted both sides of). An answer that is not a log of `rid`'s, or cannot be read, counts
 *  for nothing; it is not an error for the others. */
export async function readWitnessedLog(rid: string, answers: unknown[]): Promise<WitnessedLog> {
  const refuse = (why: string): never => {
    throw new Error("the witnesses' key log is refused: " + why);
  };
  const receipts = new Map<string, { witness: string; sig: string }[]>();
  const candidates: { texts: string[]; checked: CheckedLog; through: number }[] = [];
  const read: { texts: string[]; sigs: string[]; checked: CheckedLog }[] = [];
  for (const a of answers) {
    const ans = a as WitnessAnswer;
    if (!ans || typeof ans !== "object" || ans.aid !== rid || !Array.isArray(ans.kel) || !ans.kel.length || ans.kel.length > MAX_LOG_EVENTS) continue;
    const texts: string[] = [];
    const sigs: string[] = [];
    let ok = true;
    for (const e of ans.kel as WitnessedEvent[]) {
      const raw = strictBase64(e?.raw_bytes_b64);
      const sig = e?.cesr_signature;
      if (!raw || typeof sig !== "string" || sig.length !== 88) {
        ok = false;
        break;
      }
      try {
        texts.push(new TextDecoder("utf-8", { fatal: true }).decode(raw));
      } catch {
        ok = false;
        break;
      }
      sigs.push(sig);
    }
    if (!ok) continue;
    let checked: CheckedLog;
    try {
      checked = await readAnswerLog(rid, b64u(utf8.encode(texts.map((t, i) => t + "-AAB" + sigs[i]).join(""))), (why): never => {
        throw new Error(why);
      });
    } catch {
      continue;
    }
    // Only an identifier whose inception names witnesses and asks for a receipt has a log they vouch for.
    let icp: Ev = {};
    try {
      icp = JSON.parse(texts[0]);
    } catch {
      continue;
    }
    if (!strings(icp.b)?.length || !toadOf(icp)) continue;
    read.push({ texts, sigs, checked });
    (ans.kel as WitnessedEvent[]).forEach((e, i) => {
      const list = e.witness_receipts;
      if (!Array.isArray(list)) return;
      for (const r of list as { witness?: unknown; cesr_signature?: unknown }[]) {
        if (typeof r?.witness !== "string" || typeof r?.cesr_signature !== "string") continue;
        const said = checked.events[i].said;
        receipts.set(said, [...(receipts.get(said) ?? []), { witness: r.witness, sig: r.cesr_signature }]);
      }
    });
  }
  if (!read.length) refuse("no witness gave a key log of this identifier that can be read");
  for (const r of read) candidates.push({ texts: r.texts, checked: r.checked, through: await receiptedThrough(r.texts, receipts) });

  // Two logs that both hold an event at a place must hold the same one, as far as either is receipted.
  for (const x of candidates) {
    for (const y of candidates) {
      const reach = Math.min(x.through, y.through);
      for (let i = 0; i < reach; i++) if (x.checked.events[i].said !== y.checked.events[i].said) refuse("two logs, each receipted, disagree on an event");
    }
  }
  const best = candidates.reduce((a, b) => (b.through > a.through ? b : a));
  if (best.through === 0) refuse("no event of it has its threshold of witness receipts");
  const sigsOf = read[candidates.indexOf(best)].sigs;
  const texts = best.texts.slice(0, best.through);
  const stream = texts.map((t, i) => t + "-AAB" + sigsOf[i]).join("");
  const log = b64u(utf8.encode(stream));
  const checked = await readAnswerLog(rid, log, (why): never => {
    throw new Error(why);
  });
  return { log, events: best.through, checked };
}

/** How the log a link carried stands to the log the witnesses vouch for:
 *  - `agrees`: the link's log holds every event they vouch for (and perhaps more, which they have not been told yet);
 *  - `moved_on`: they vouch for events after the link's last, so the key the link vouched a sealing key for is not current;
 *  - `apart`: the two have different events at one place;
 *  - `none`: the witnesses gave no log a page can take (none reached, none receipted, none readable). */
export type LinkVerdict = "agrees" | "moved_on" | "apart" | "none";

/** Judges `linkLog` (a log already read from the link, base64url) against the `answers` of the identifier's witnesses.
 *  `log` is the witnessed log to remember when there is one, which is what keeps a link made before a rotation
 *  refused afterwards. */
export async function judgeLinkLog(rid: string, linkLog: string, answers: unknown[]): Promise<{ verdict: LinkVerdict; log?: string }> {
  let w: WitnessedLog;
  try {
    w = await readWitnessedLog(rid, answers);
  } catch {
    return { verdict: "none" };
  }
  const mine = await readAnswerLog(rid, linkLog, (why): never => {
    throw new Error(why);
  });
  if (logExtends(mine.events, w.checked.events)) return { verdict: "agrees", log: w.log };
  if (logExtends(w.checked.events, mine.events)) return { verdict: "moved_on", log: w.log };
  return { verdict: "apart", log: w.log };
}

/** The most a page takes of one witness's answer. */
const MAX_WITNESS_ANSWER = 512 << 10;
const WITNESS_TIMEOUT_MS = 8000;

/** Asks each witness address (`<address>/witness/kel/<rid>`) for the log, presenting `inception` (the identifier's
 *  first event as published) in X-Inception-Event, which is all that lets a page read it. Every address is asked at
 *  once; one that cannot be reached, answers anything but 200 with JSON, or answers too much, gives nothing. */
export async function askWitnesses(rid: string, inception: string, addresses: string[], ask: typeof fetch): Promise<unknown[]> {
  const proof = b64u(utf8.encode(inception));
  const got = await Promise.all(
    addresses.map(async (address) => {
      try {
        const ctl = new AbortController();
        const timer = setTimeout(() => ctl.abort(), WITNESS_TIMEOUT_MS);
        try {
          const r = await ask(`${address}/witness/kel/${encodeURIComponent(rid)}`, { method: "GET", headers: { "X-Inception-Event": proof }, signal: ctl.signal });
          if (r.status !== 200) return null;
          const text = await r.text();
          return text.length > MAX_WITNESS_ANSWER ? null : JSON.parse(text);
        } finally {
          clearTimeout(timer);
        }
      } catch {
        return null;
      }
    }),
  );
  return got.filter((a) => a !== null);
}
