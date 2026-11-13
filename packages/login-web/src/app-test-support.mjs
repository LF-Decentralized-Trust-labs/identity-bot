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

// A back end's sealing key, vouched for by `relay` (the relay identifier), and what answers
// sealed calls: `wrap(inner)` takes a back end written as a plain `fetch` (url, init) -> Response
// (what the tests wrote before sealing) and makes the `fetchFn` a page is given: it opens the
// one POST to /sealed, runs `inner` on the call inside, and seals what `inner` answered (status,
// content type, body, and the app's signature headers) for the page.
import { webcrypto } from "node:crypto";
import { openRequest, SEAL_PATH, sealKeyStatementText } from "../dist/seal.js";

/** A sealing key's statement as the relay identifier's current key makes it: the whole key log, the key,
 *  the log's last sequence number, and the signature over them (`sealKeyStatementText`). */
export function sealStatement(relay, pub, over = {}) {
  const sn = over.sn ?? relay.events.length - 1;
  return b64u(JSON.stringify({ log: over.log ?? relay.log(), key: b64u(pub), sn, sig: b64u((over.signer ?? relay).sign(sealKeyStatementText(relay.aid, pub, sn))) }));
}

/** The link's `min` for a relay identifier: its latest event as `<sequence number>.<SAID>`
 *  (the first `n` events when given), as the owner's Identity Agent writes it. */
export function minimum(relay, n = relay.events.length) {
  return `${n - 1}.${relay.events[n - 1].said}`;
}

/** `clock` (`{ now: () => ms }`) makes the wrapped back end take only calls dated within two minutes of it, and
 *  answer another with the signed, sealed 409 that tells the time (ADR-072 Amendment 4). */
export async function sealing(relay, origin = "https://tasks.example") {
  const pair = await webcrypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const pub = new Uint8Array(await webcrypto.subtle.exportKey("raw", pair.publicKey));
  const statement = sealStatement(relay, pub);
  const title = (n) => n.replace(/(^|-)([a-z])/g, (_, d, c) => d + c.toUpperCase());
  const seen = [];
  const wrap = (inner, rid = relay.aid, clock = null) => async (url, init) => {
    seen.push({ url: String(url), method: init.method, body: init.body });
    if (new URL(String(url)).pathname !== SEAL_PATH || init.method !== "POST") return new Response("not here", { status: 404 });
    const { content, reply } = await openRequest(rid, pair, init.body);
    const call = JSON.parse(new TextDecoder().decode(content));
    const headers = Object.fromEntries(Object.entries(call.headers).map(([k, v]) => [title(k), v]));
    seen.at(-1).ts = call.ts;
    if (clock && Math.abs(Date.parse(call.ts) - clock.now()) > 120_000) {
      const body = enc.encode(JSON.stringify({ error: "clock", server_time: new Date(clock.now()).toISOString().replace(/\.\d{3}Z$/, "Z") }));
      const { answerText } = await import("../dist/app.js");
      const sig = b64u(relay.sign(enc.encode(await answerText(relay.aid, call.headers["x-browser-answer-nonce"], 409, "application/json", body))));
      const clockAnswer = JSON.stringify({ status: 409, content_type: "application/json", body: b64u(body), log: relay.log(), sig });
      return new Response(await reply.seal(enc.encode(clockAnswer)), { status: 200, headers: { "content-type": "application/json" } });
    }
    const r = await inner(origin + call.target, { method: call.method, headers, body: call.method === "GET" ? undefined : call.body });
    const bytes = new Uint8Array(await r.arrayBuffer());
    const answer = JSON.stringify({ status: r.status, content_type: r.headers.get("content-type") ?? "", body: b64u(bytes),
      log: r.headers.get("x-keri-app-answer-log"), sig: r.headers.get("x-keri-app-answer-sig") });
    return new Response(await reply.seal(enc.encode(answer)), { status: 200, headers: { "content-type": "application/json" } });
  };
  return { pair, statement, min: minimum(relay), wrap, seen };
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
export function inception(k, next, w = {}) {
  const b = JSON.stringify(w.b ?? []);
  const ev = sealed((v, d) => `{"v":"${v}","t":"icp","d":"${d}","i":"${d}","s":"0","kt":"1","k":["${k.key}"],"nt":"1","n":["${next.digest}"],"bt":"${w.bt ?? "0"}","b":${b},"c":[],"a":[]}`);
  return { ...ev, aid: ev.said };
}

/** A rotation to key `k`, committing to `next`, carrying on from the event whose SAID is `prior`. */
export function rotation(aid, sn, prior, k, next, over = {}) {
  const s = over.s ?? sn.toString(16);
  return sealed((v, d) => `{"v":"${v}","t":"rot","d":"${d}","i":"${aid}","s":"${s}","p":"${over.p ?? prior}","kt":"1","k":["${k.key}"],"nt":"1","n":["${next.digest}"],"bt":"${over.bt ?? "0"}","br":${JSON.stringify(over.br ?? [])},"ba":${JSON.stringify(over.ba ?? [])},"a":[]}`);
}

/** A key log as the header carries it: each event with its signer's signature, base64url. */
export function logHeader(events) {
  return b64u(events.map((e) => e.text + "-AAB" + indexedSigQb64((e.signer ?? e.by).sign(enc.encode(e.text)))).join(""));
}

/** A relay identifier rotated `rotations` times: keys k0..kN, and its events, each signed by the key it names. */
export function relayChain(label, rotations = 0, w = {}) {
  const keys = Array.from({ length: rotations + 2 }, (_, i) => keyFor(`${label}:${i}`));
  const icp = inception(keys[0], keys[1], w);
  const events = [{ ...icp, signer: keys[0] }];
  for (let i = 1; i <= rotations; i++) {
    events.push({ ...rotation(icp.aid, i, events[i - 1].said, keys[i], keys[i + 1], { bt: w.bt ?? "0", ...(w.over?.[i] ?? {}) }), signer: keys[i] });
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

/** The `iat` of a link made just now: whole seconds since 1970. */
export const nowSeconds = () => Math.floor(Date.now() / 1000);

// ---- a witness, and what it answers --------------------------------------
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** A witness made from a label: a non-transferable identifier (its key with code B), and its receipts. */
export function witnessFor(label) {
  const k = keyFor("witness:" + label);
  const aid = "B" + k.key.slice(1);
  /** The witness's receipt of an event's text, indexed at its place in the list. */
  const receipt = (text, index) => ({ witness: aid, cesr_signature: "A" + B64[index] + indexedSigQb64(k.sign(enc.encode(text))).slice(2) });
  return { aid, receipt, sign: k.sign };
}

/** What a witness answers to GET /witness/kel/{rid}: the events of `chain` it holds (its first `n`),
 *  each with its bytes, the controller's signature, and the receipts given (a list per event). */
export function witnessAnswer(chain, n, receiptsFor = () => []) {
  return { aid: chain.aid, kel: chain.events.slice(0, n).map((e, i) => ({
    raw_bytes_b64: Buffer.from(e.text).toString("base64"),
    cesr_signature: indexedSigQb64(e.signer.sign(enc.encode(e.text))),
    ...(receiptsFor(i, e).length ? { witness_receipts: receiptsFor(i, e) } : {}),
  })) };
}
