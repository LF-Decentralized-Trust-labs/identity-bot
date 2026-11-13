/**
 * A relay identifier's key log as a page reads it (ADR-072): the one reader the answer's log,
 * the sealing key's statement, the page's memory and the witnesses' log (`witnessed.ts`) all use.
 */
import { blake3Qb64, decodeBase64UrlStrict, decodeMatterRaw, verifyEd25519 } from "@identity-agent/login-verify/browser";

const utf8 = new TextEncoder();

/** Fails unless `aid` is the digest of the inception `text` with d and i
 *  blanked, which is what makes an identifier self-addressing. */
export function deriveIdentifier(text: string, aid: string, fail: (why: string) => never): void {
  const blank = "#".repeat(aid.length);
  let dummy = text;
  for (const f of ["d", "i"]) {
    const needle = `"${f}":"${aid}"`;
    if (dummy.split(needle).length !== 2) fail(`its event names ${f} other than once`);
    dummy = dummy.replace(needle, `"${f}":"${blank}"`);
  }
  if (blake3Qb64(utf8.encode(dummy)) !== aid) fail("its inception does not derive the identifier");
}

/** The most a relay takes of a key log (relayproto.MaxKELBytes, MaxKELEvents). */
export const MAX_LOG_BYTES = 64 << 10;
export const MAX_LOG_EVENTS = 256;

export interface LogEvent {
  sn: number;
  ilk: string;
  said: string;
}

export interface CheckedLog {
  /** The key the log names now. */
  key: Uint8Array;
  events: LogEvent[];
  /** The inception event as published: what a witness is shown to prove the log is known (X-Inception-Event). */
  inception: string;
}

/** Reads the signed key log a relay identifier's answer carries (a CESR stream:
 *  each event's JSON followed by exactly one controller signature group) and
 *  returns the key it names now. Throws, saying why, unless the log is the
 *  identifier `rid`'s own from its inception: every event's SAID derives, each
 *  rotation carries on from the one before (sequence number, prior SAID), is
 *  made with exactly the key the event before committed to, and every event is
 *  signed by the key it names. One key at a time, and only an inception and
 *  rotations: the identifiers an app serves under have no other kind of event,
 *  so anything else is refused rather than skipped. */
export async function readAnswerLog(rid: string, encoded: string | null | undefined, fail: (why: string) => never): Promise<CheckedLog> {
  const bytes = decodeBase64UrlStrict(encoded ?? "");
  if (!bytes || !bytes.length) fail("it is not signed");
  if (bytes!.length > MAX_LOG_BYTES) fail("its key log is larger than a relay takes");
  if (bytes!.some((b) => b >= 0x80)) fail("its key log is not text");
  let text = "";
  for (let o = 0; o < bytes!.length; o += 8192) text += String.fromCharCode(...bytes!.subarray(o, o + 8192));
  const parts: { event: string; sig: string }[] = [];
  for (let pos = 0; pos < text.length; ) {
    const head = /^\{"v":"KERI10JSON([0-9a-f]{6})_"/.exec(text.slice(pos, pos + 40));
    if (!head) fail("its key log has something that is not an event where one must begin");
    const len = parseInt(head![1], 16);
    const event = text.slice(pos, pos + len);
    if (event.length !== len || !event.endsWith("}")) fail("an event of its key log is not as long as it says");
    pos += len;
    // Exactly one controller signature (one key, so one place), as the relay makes them.
    if (!text.startsWith("-AAB", pos) || pos + 92 > text.length) fail("an event of its key log is not followed by exactly one signature");
    parts.push({ event, sig: text.slice(pos + 4, pos + 92) });
    pos += 92;
    if (parts.length > MAX_LOG_EVENTS) fail("its key log has more events than a relay takes");
  }
  if (!parts.length) fail("it is not signed");

  const events: LogEvent[] = [];
  let key: Uint8Array | undefined;
  let prev: { d: string; n: string } | undefined;
  for (let i = 0; i < parts.length; i++) {
    const { event, sig } = parts[i];
    let ev: { t?: string; d?: string; i?: string; s?: string; p?: string; di?: string; kt?: string; k?: string[]; nt?: string; n?: string[] };
    try {
      ev = JSON.parse(event);
    } catch {
      return fail("an event of its key log is unreadable");
    }
    if (typeof ev.d !== "string" || !ev.d) fail("an event of its key log has no SAID");
    if (i === 0) {
      if (ev.t !== "icp" || ev.i !== rid || ev.d !== rid || ev.di) fail("its inception is not the identifier the link names");
      if (ev.s !== "0") fail("its inception is not sequence number 0");
      deriveIdentifier(event, rid, fail);
    } else {
      if (ev.t !== "rot" || ev.i !== rid) fail("an event after the inception is not a rotation of the identifier the link names");
      if (ev.s !== i.toString(16)) fail("a rotation is out of sequence");
      if (ev.p !== prev!.d) fail("a rotation does not carry on from the event before it");
      const needle = `"d":"${ev.d}"`;
      if (event.split(needle).length !== 2) fail("a rotation names its SAID other than once");
      if (blake3Qb64(utf8.encode(event.replace(needle, `"d":"${"#".repeat(ev.d.length)}"`))) !== ev.d) fail("a rotation's SAID is not the digest of the rotation");
    }
    if (ev.kt !== "1" || !Array.isArray(ev.k) || ev.k.length !== 1 || ev.nt !== "1" || !Array.isArray(ev.n) || ev.n.length !== 1 || typeof ev.n[0] !== "string") {
      fail("only a single-key identity that commits to its next key is read");
    }
    const k = decodeMatterRaw(ev.k![0], "D", 32);
    if (!k) fail("its key is not spelled one way");
    // A rotation is made with exactly the key the event before committed to.
    if (prev && blake3Qb64(utf8.encode(ev.k![0])) !== prev.n) fail("a rotation is made with a key the event before did not commit to");
    const raw = decodeMatterRaw(sig, "AA", 64);
    if (!raw) fail("an event's signature is not spelled one way");
    if (!(await verifyEd25519(raw!, utf8.encode(event), k!))) fail("an event of its key log is not signed by the key it names");
    key = k!;
    prev = { d: ev.d, n: ev.n![0] };
    events.push({ sn: i, ilk: ev.t as string, said: ev.d });
  }
  return { key: key!, events, inception: parts[0].event };
}


/** Whether `log` holds every event `base` holds, in the same order, and perhaps
 *  more after them: the one rule for taking a newer log in place of one already
 *  held. Events are compared by sequence number, type and SAID. */
export function logExtends(log: LogEvent[], base: LogEvent[]): boolean {
  return log.length >= base.length && base.every((e, i) => log[i].sn === e.sn && log[i].ilk === e.ilk && log[i].said === e.said);
}
