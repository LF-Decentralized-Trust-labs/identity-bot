// Makes test-vectors/app-checks.json: what a utility app's page believes (src/app.ts) and what a
// port in another language must believe alike. Every key is derived from a fixed seed and Ed25519
// signs deterministically, so the file is the same every time it is made (the test makes it again
// and compares). Run `node test-vectors/make-app-checks.mjs` after `npm run build` to rewrite it.
import { createHash, createPrivateKey, createPublicKey, sign as edSign } from "node:crypto";
import { writeFileSync } from "node:fs";
import { blake3Qb64, ed25519SigQb64, ed25519VerkeyQb64 } from "../../login-verify/dist/browser.js";
import { answerText, browserKeyThumbprint, proofText } from "../dist/app.js";
import { inception, keyFor, logHeader, relayChain, rotation } from "../src/app-test-support.mjs";

const enc = new TextEncoder();
const b64u = (b) => Buffer.from(b).toString("base64url");
const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");

function identity(label) {
  const seed = createHash("sha256").update("app-checks:" + label).digest();
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: "der", type: "pkcs8" });
  const pub = Buffer.from(createPublicKey(priv).export({ format: "jwk" }).x, "base64url");
  const key = ed25519VerkeyQb64(new Uint8Array(pub));
  const blank = "#".repeat(44);
  const ev = (d) => `{"v":"KERI10JSON000000_","t":"icp","d":"${d}","i":"${d}","s":"0","kt":"1","k":["${key}"],"nt":"1","n":[],"bt":"0","b":[],"c":[],"a":[]}`;
  const aid = blake3Qb64(enc.encode(ev(blank)));
  const text = ev(aid);
  const sign = (bytes) => new Uint8Array(edSign(null, Buffer.from(bytes), priv));
  const log = (over = {}) => b64u(JSON.stringify({ raw_events_b64: [Buffer.from(text).toString("base64")], cesr_signatures: [ed25519SigQb64(sign(enc.encode(text)))], ...over }));
  return { aid, key: pub, text, sign, log };
}

export async function make() {
  const app = identity("app");
  const relay = identity("relay");
  const other = identity("other");
  const hex = (b) => Buffer.from(b).toString("hex");
  const x = b64u(new Uint8Array(32).fill(1)), y = b64u(new Uint8Array(32).fill(2));
  const thumb = browserKeyThumbprint({ x, y });
  const NOW = Date.parse("2026-11-11T12:00:00Z");

  const links = [
    { name: "a complete link", hash: `#aid=${app.aid}&kel=${app.log()}&rid=${relay.aid}&api=https://tasks.example/`, expect: { aid: app.aid, kel: app.log(), rid: relay.aid, api: "https://tasks.example" } },
    { name: "no relay identifier", hash: `#aid=${app.aid}&kel=x&api=https://a.example`, refuse: "no relay identifier" },
    { name: "a back end that is not https or local", hash: `#aid=${app.aid}&kel=x&rid=${relay.aid}&api=http://evil.example`, refuse: "no back end" },
    { name: "a local back end", hash: `#aid=${app.aid}&kel=x&rid=${relay.aid}&api=http://127.0.0.1:9`, expect: { aid: app.aid, kel: "x", rid: relay.aid, api: "http://127.0.0.1:9" } },
  ];

  const keyLogs = [];
  const kl = (name, aid, encoded, refuse) => keyLogs.push({ name, aid, encoded, ...(refuse ? { refuse } : { expect_key_hex: hex(app.key) }) });
  kl("the app's own log", app.aid, app.log());
  kl("another identifier's log", relay.aid, app.log(), "not the app's identifier");
  kl("a wrong signature", app.aid, app.log({ cesr_signatures: [ed25519SigQb64(new Uint8Array(64))] }), "not signed by the key");
  kl("fields it should not have", app.aid, b64u(JSON.stringify({ raw_events_b64: [], cesr_signatures: [], extra: 1 })), "fields it should not");
  { const forged = identity("forged");
    const text = forged.text.replaceAll(forged.aid, app.aid);
    kl("a self-signed event under another's identifier", app.aid,
      b64u(JSON.stringify({ raw_events_b64: [Buffer.from(text).toString("base64")], cesr_signatures: [ed25519SigQb64(forged.sign(enc.encode(text)))] })), "does not derive the identifier"); }

  const challenges = [];
  const ch = (name, over, o = {}) => {
    const body = JSON.stringify({ v: "ASK1", t: 1, site_aid: app.aid, browser_key: thumb, expiry: "2026-11-11T12:10:00Z", session_token: "tok", ...over });
    const signer = o.signer ?? app;
    const c = { name, aid: app.aid, key_hex: hex(app.key), body, sig: ed25519SigQb64(signer.sign(enc.encode(body))),
      pointer: o.pointer ?? "https://ia.example/i/tok", own_thumbprint: o.own ?? thumb, now_ms: NOW };
    challenges.push(o.refuse ? { ...c, refuse: o.refuse } : { ...c, expect: { session_token: "tok", expiry: "2026-11-11T12:10:00Z", ...(over.front_end ? { front_end: over.front_end } : {}) } });
  };
  ch("the app's challenge for this key", {});
  ch("a challenge naming the browser kind", { front_end: "browser" });
  ch("an installed-app challenge", { front_end: "installed_app" }, { refuse: "another kind of front end" });
  ch("another browser's key", { browser_key: "x".repeat(43) }, { refuse: "this page's own key" });
  ch("another app's challenge", { site_aid: relay.aid }, { refuse: "another app" });
  ch("a lapsed challenge", { expiry: "2026-11-11T11:59:59Z" }, { refuse: "lapsed" });
  ch("signed by another key", {}, { signer: other, refuse: "not signed by the app" });
  ch("another challenge's code", {}, { pointer: "https://ia.example/i/other", refuse: "not this challenge's" });
  ch("a code that is not https", {}, { pointer: "http://ia.example/i/tok", refuse: "not this challenge's" });

  // What the app answers with is signed by the CURRENT key of its relay identifier, and the answer
  // carries that identifier's whole signed key log. `chain` is one rotated twice: keys k0 (the first
  // machine's), k1, k2 (current); `known` is the longest log the page already holds for it.
  const chain = relayChain("relay-chain", 2);
  const unrotated = relayChain("relay-chain", 0); // the same keys, before any rotation: the same identifier
  const body = enc.encode('{"ok":true}');
  const answers = [];
  const an = async (name, o = {}) => {
    const rid = o.rid ?? chain.aid;
    const nonce = o.nonce ?? "n1";
    const sigBy = o.sigBy ?? chain.keys[2];
    const signed = b64u(sigBy.sign(enc.encode(await answerText(rid, "n1", 200, "application/json", body))));
    const a = { name, rid, nonce, status: o.status ?? 200, content_type: "application/json", body_b64: Buffer.from(o.body ?? body).toString("base64"),
      log: o.log === undefined ? chain.log() : o.log, known: o.known ?? null, sig: o.sig === undefined ? signed : o.sig };
    answers.push(o.refuse ? { ...a, refuse: o.refuse } : { ...a, expect_log: o.expect_log ?? a.log });
  };
  // the same cases whatever the log, rotated or not
  await an("the app's answer to this call, rotated twice", {});
  await an("an app that has not rotated", { rid: unrotated.aid, log: unrotated.log(), sigBy: unrotated.keys[0] });
  await an("a rotated app, the page already holds its log up to the first rotation", { known: chain.log(2) });
  await an("a rotated app, the page already holds the same log", { known: chain.log() });
  await an("an answer to another call", { nonce: "n2", refuse: "does not hold for this call" });
  await an("a changed body", { body: enc.encode('{"ok":false}'), refuse: "does not hold for this call" });
  await an("a changed status", { status: 500, refuse: "does not hold for this call" });
  await an("an unsigned answer", { sig: null, refuse: "not signed" });
  await an("no key log", { log: null, refuse: "not signed" });
  await an("a link naming another identifier", { rid: app.aid, refuse: "not the identifier the link names" });
  // the key the log has left
  await an("the first machine's key with its own short log, before the rotation was seen", { log: chain.log(1), sigBy: chain.keys[0], expect_log: chain.log(1) });
  await an("the first machine's key with its own short log, after the rotation was seen", { log: chain.log(1), sigBy: chain.keys[0], known: chain.log(), refuse: "behind or apart" });
  await an("an intermediate roll-back", { log: chain.log(2), sigBy: chain.keys[1], known: chain.log(), refuse: "behind or apart" });
  await an("the first machine's key under the current log", { sigBy: chain.keys[0], refuse: "does not hold for this call" });
  await an("the previous key under the current log", { sigBy: chain.keys[1], refuse: "does not hold for this call" });
  { // a fork: a rotation to the committed key (k1) that commits to another next key, so every later event differs
    const icp = chain.events[0];
    const fork = { ...rotation(chain.aid, 1, icp.said, chain.keys[1], keyFor("a-fork:next")), signer: chain.keys[1] };
    await an("a fork of the log the page already holds", { log: logHeader([icp, fork]), sigBy: chain.keys[1], known: chain.log(), refuse: "behind or apart" });
  }
  { // a rotation to a key the event before did not commit to, signed with that key
    const stray = keyFor("a-stray");
    const bad = { ...rotation(chain.aid, 1, chain.events[0].said, stray, keyFor("a-stray:next")), signer: stray };
    await an("a rotation to a key that was not committed to", { log: logHeader([chain.events[0], bad]), sigBy: stray, refuse: "did not commit to" });
  }
  { // a rotation signed by the key before it, not the key it names
    const e = chain.events[1];
    await an("a rotation signed by the key it replaces", { log: logHeader([chain.events[0], { ...e, signer: chain.keys[0] }]), sigBy: chain.keys[1], refuse: "not signed by the key it names" });
  }
  { const e = rotation(chain.aid, 1, chain.events[0].said, chain.keys[1], chain.keys[2], { s: "2" });
    await an("a rotation out of sequence", { log: logHeader([chain.events[0], { ...e, signer: chain.keys[1] }]), sigBy: chain.keys[1], refuse: "out of sequence" }); }
  { const e = rotation(chain.aid, 1, chain.events[0].said, chain.keys[1], chain.keys[2], { p: chain.aid.slice(0, -1) + "A" });
    await an("a rotation that does not carry on from the event before it", { log: logHeader([chain.events[0], { ...e, signer: chain.keys[1] }]), sigBy: chain.keys[1], refuse: "carry on from the event before" }); }
  { // an event changed after its SAID was made
    const e = chain.events[1];
    const text = e.text.replace('"bt":"0"', '"bt":"1"');
    await an("a rotation changed after it was made", { log: logHeader([chain.events[0], { ...e, text, signer: chain.keys[1] }]), sigBy: chain.keys[1], refuse: "not the digest of the rotation" }); }
  { // a log of another identifier presented under this one's name
    const other2 = relayChain("some-other-relay", 1);
    await an("another identifier's log", { log: other2.log(), sigBy: other2.keys[1], refuse: "not the identifier the link names" }); }
  await an("a log with an event cut short", { log: b64u(Buffer.from(chain.log(), "base64url").subarray(0, -10)), refuse: "not followed by exactly one signature" });
  await an("a log with something after it", { log: b64u(Buffer.concat([Buffer.from(chain.log(), "base64url"), Buffer.from("x")])), refuse: "not an event where one must begin" });

  const proofs = [];
  for (const p of [
    { method: "GET", target: "/signin/session/abc?x=1", ts: "2026-11-11T12:00:05Z", nonce: "nonce1", binding: "abc", body: "" },
    { method: "POST", target: "/session/chat/send", ts: "2026-11-11T12:00:06Z", nonce: "nonce2", binding: "bindingvalue", body: '{"words":"héllo"}' },
  ]) proofs.push({ ...p, expect: await proofText(p.method, p.target, p.ts, p.nonce, p.binding, p.body) });

  const answerTexts = [{ rid: chain.aid, nonce: "n1", status: 200, content_type: "application/json", body_b64: Buffer.from(body).toString("base64"), expect: await answerText(chain.aid, "n1", 200, "application/json", body) }];
  const thumbprints = [{ x, y, expect: thumb }];
  const skews = [
    { server_time: "2026-11-11T12:00:10Z", now_ms: NOW, expect_ms: 10000 },
    { server_time: "tomorrow", now_ms: NOW, refuse: "no time" },
  ];
  return {
    about: "What a utility app's page believes (packages/login-web/src/app.ts), as cases a port in another language must hold alike. Made by make-app-checks.mjs; the TypeScript test makes it again and compares. A case with `refuse` must be refused with a message containing that text; otherwise it must give `expect`.",
    links, key_logs: keyLogs, challenges, answers, proofs, answer_texts: answerTexts, thumbprints, skews,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  writeFileSync(new URL("./app-checks.json", import.meta.url), JSON.stringify(await make(), null, 2) + "\n");
}
