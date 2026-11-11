// Makes test-vectors/app-checks.json: what a utility app's page believes (src/app.ts) and what a
// port in another language must believe alike. Every key is derived from a fixed seed and Ed25519
// signs deterministically, so the file is the same every time it is made (the test makes it again
// and compares). Run `node test-vectors/make-app-checks.mjs` after `npm run build` to rewrite it.
import { createHash, createPrivateKey, createPublicKey, sign as edSign } from "node:crypto";
import { writeFileSync } from "node:fs";
import { blake3Qb64, ed25519SigQb64, ed25519VerkeyQb64 } from "../../login-verify/dist/browser.js";
import { answerText, browserKeyThumbprint, proofText } from "../dist/app.js";

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

  const answers = [];
  const body = enc.encode('{"ok":true}');
  const an = async (name, o = {}) => {
    const nonce = o.nonce ?? "n1";
    const signed = b64u(relay.sign(enc.encode(await answerText(relay.aid, "n1", 200, "application/json", body))));
    const a = { name, rid: o.rid ?? relay.aid, nonce, status: o.status ?? 200, content_type: "application/json", body_b64: Buffer.from(o.body ?? body).toString("base64"),
      inception: b64u(enc.encode(relay.text)), sig: o.sig === undefined ? signed : o.sig };
    answers.push(o.refuse ? { ...a, refuse: o.refuse } : a);
  };
  await an("the app's answer to this call");
  await an("an answer to another call", { nonce: "n2", refuse: "does not hold for this call" });
  await an("a changed body", { body: enc.encode('{"ok":false}'), refuse: "does not hold for this call" });
  await an("a changed status", { status: 500, refuse: "does not hold for this call" });
  await an("an unsigned answer", { sig: null, refuse: "not signed" });
  await an("another identifier", { rid: app.aid, refuse: "not the identifier the link names" });

  const proofs = [];
  for (const p of [
    { method: "GET", target: "/signin/session/abc?x=1", ts: "2026-11-11T12:00:05Z", nonce: "nonce1", binding: "abc", body: "" },
    { method: "POST", target: "/session/chat/send", ts: "2026-11-11T12:00:06Z", nonce: "nonce2", binding: "bindingvalue", body: '{"words":"héllo"}' },
  ]) proofs.push({ ...p, expect: await proofText(p.method, p.target, p.ts, p.nonce, p.binding, p.body) });

  const answerTexts = [{ rid: relay.aid, nonce: "n1", status: 200, content_type: "application/json", body_b64: Buffer.from(body).toString("base64"), expect: await answerText(relay.aid, "n1", 200, "application/json", body) }];
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
