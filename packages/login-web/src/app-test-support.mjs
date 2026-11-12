// What the tests of a utility app's page share: an identity with a one-event
// key log, made the way a core makes one.
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign } from "node:crypto";
import { blake3Qb64, ed25519SigQb64, ed25519VerkeyQb64 } from "../../login-verify/dist/browser.js";

export const enc = new TextEncoder();
export const b64u = (b) => Buffer.from(b).toString("base64url");

export function identity() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
  const key = ed25519VerkeyQb64(new Uint8Array(pub));
  const blank = "#".repeat(44);
  const ev = (d) => `{"v":"KERI10JSON000000_","t":"icp","d":"${d}","i":"${d}","s":"0","kt":"1","k":["${key}"],"nt":"1","n":[],"bt":"0","b":[],"c":[],"a":[]}`;
  const aid = blake3Qb64(enc.encode(ev(blank)));
  const text = ev(aid);
  const sign = (bytes) => edSign(null, Buffer.from(bytes), privateKey);
  const log = (over = {}) => b64u(JSON.stringify({ raw_events_b64: [Buffer.from(text).toString("base64")], cesr_signatures: [ed25519SigQb64(new Uint8Array(sign(enc.encode(text))))], ...over }));
  return { aid, key: new Uint8Array(pub), text, sign, log };
}

// ---- a relay identifier's key log, made the way a core makes one ----------
// (keri-go BuildInception / BuildRotation / SignEvent / ExportKEL): each event's JSON
// with its real length in the version string and its SAID, followed by one signature group.
const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");

/** A key made from a label, so the same label gives the same key every time. */
export function keyFor(label) {
  const seed = createHash("sha256").update("app-checks:" + label).digest();
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: "der", type: "pkcs8" });
  const pub = new Uint8Array(Buffer.from(createPublicKey(priv).export({ format: "jwk" }).x, "base64url"));
  const key = ed25519VerkeyQb64(pub);
  return { label, pub, key, digest: blake3Qb64(enc.encode(key)), sign: (bytes) => new Uint8Array(edSign(null, Buffer.from(bytes), priv)) };
}

/** An indexed Ed25519 signature, place 0, the way a log carries it (88 characters). */
export const indexedSigQb64 = (raw) => "AA" + Buffer.concat([Buffer.alloc(2), Buffer.from(raw)]).toString("base64url").slice(2);

function sealed(template) {
  const blank = "#".repeat(44);
  const v = `KERI10JSON${template("KERI10JSON000000_", blank).length.toString(16).padStart(6, "0")}_`;
  const d = blake3Qb64(enc.encode(template(v, blank)));
  return { text: template(v, d), said: d };
}

/** The inception of an identifier whose first key is `k` and which commits to `next`. */
export function inception(k, next) {
  const ev = sealed((v, d) => `{"v":"${v}","t":"icp","d":"${d}","i":"${d}","s":"0","kt":"1","k":["${k.key}"],"nt":"1","n":["${next.digest}"],"bt":"0","b":[],"c":[],"a":[]}`);
  return { ...ev, aid: ev.said };
}

/** A rotation to key `k`, committing to `next`, carrying on from the event whose SAID is `prior`. */
export function rotation(aid, sn, prior, k, next, over = {}) {
  const s = over.s ?? sn.toString(16);
  return sealed((v, d) => `{"v":"${v}","t":"rot","d":"${d}","i":"${aid}","s":"${s}","p":"${over.p ?? prior}","kt":"1","k":["${k.key}"],"nt":"1","n":["${next.digest}"],"bt":"0","br":[],"ba":[],"a":[]}`);
}

/** A key log as the header carries it: each event with its signer's signature, base64url. */
export function logHeader(events) {
  return b64u(events.map((e) => e.text + "-AAB" + indexedSigQb64((e.signer ?? e.by).sign(enc.encode(e.text)))).join(""));
}

/** A relay identifier rotated `rotations` times: keys k0..kN, and its events, each signed by the key it names. */
export function relayChain(label, rotations = 0) {
  const keys = Array.from({ length: rotations + 2 }, (_, i) => keyFor(`${label}:${i}`));
  const icp = inception(keys[0], keys[1]);
  const events = [{ ...icp, signer: keys[0] }];
  for (let i = 1; i <= rotations; i++) {
    events.push({ ...rotation(icp.aid, i, events[i - 1].said, keys[i], keys[i + 1]), signer: keys[i] });
  }
  const upTo = (n) => events.slice(0, n);
  return { aid: icp.aid, keys, events, log: (n = events.length) => logHeader(upTo(n)), key: (i) => keys[i],
    /** Signs with the key the whole log names now. */
    sign: (bytes) => keys[rotations].sign(bytes) };
}

/** What a page remembers of an app's key log, in the test alone. */
export function logMemory() {
  const m = new Map();
  return { get: (rid) => m.get(rid) ?? null, set: (rid, log) => m.set(rid, log) };
}
