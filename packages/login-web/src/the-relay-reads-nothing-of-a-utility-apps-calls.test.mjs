// What a relay between a utility app's page and its back end can read (ADR-072
// step 5, Amendment 4): every call is one POST to one path, its body names
// nothing of the call, and what it passes back is an answer only to that call.
import assert from "node:assert";
import { webcrypto } from "node:crypto";
import { answerText, appSession, browserKeyThumbprint, readAppLink } from "../dist/app.js";
import { b64u, enc, identity, sealing } from "./app-test-support.mjs";

const app = identity(), relay = identity();
const sl = await sealing(relay);
const L = readAppLink(`#aid=${app.aid}&kel=${app.log()}&rid=${relay.aid}&api=https://tasks.example&seal=${sl.statement}`);
const pair = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
const jwk = { kty: "EC", crv: "P-256", x: b64u(new Uint8Array(32).fill(1)), y: b64u(new Uint8Array(32).fill(2)) };
const mine = { privateKey: pair.privateKey, jwk, thumbprint: browserKeyThumbprint(jwk) };
const m = new Map();
const storage = { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => void m.set(k, v), removeItem: (k) => void m.delete(k) };

const SECRET_TOKEN = "session-token-the-relay-must-not-read";
const SECRET_PATH = "/session/chat/with-a-name-nobody-should-learn";
const SECRET_BODY = '{"words":"what the person said"}';
const answered = [];
const backEnd = async (url, init) => {
  const path = new URL(String(url)).pathname;
  answered.push({ path, headers: init.headers, body: init.body });
  const nonce = init.headers["X-Browser-Answer-Nonce"];
  const body = enc.encode(JSON.stringify(path === "/session/whoami" ? { pairwise_aid: "EP", browser_key: mine.thumbprint, server_time: "2030-01-01T00:00:00Z" } : { reply: "what the app said" }));
  const sig = b64u(relay.sign(enc.encode(await answerText(relay.aid, nonce, 200, "application/json", body))));
  return new Response(body, { status: 200, headers: { "content-type": "application/json", "x-keri-app-answer-inception": b64u(enc.encode(relay.text)), "x-keri-app-answer-sig": sig } });
};

// The relay's view: every request and answer, as it passes.
const onTheWire = [];
let tamper = (r) => r;
const viaRelay = async (url, init) => {
  const out = { method: init.method, url: String(url), headers: init.headers, body: init.body };
  const r = await sl.wrap(backEnd)(url, init);
  const text = await r.text();
  onTheWire.push({ request: out, answerText: text });
  return tamper(new Response(text, { status: r.status, headers: r.headers }), out);
};
const session = () => appSession(L, { storage, fetchFn: viaRelay, browserKey: async () => mine });

let s = session();
s.keep(SECRET_TOKEN);
const got = await s.call("POST", SECRET_PATH, SECRET_BODY);
assert.deepEqual(got.json(), { reply: "what the app said" });
assert.equal(answered.at(-1).path, SECRET_PATH, "the back end got the call");
assert.equal(answered.at(-1).headers.Authorization, "Bearer " + SECRET_TOKEN);

assert.ok(onTheWire.length >= 2);
for (const w of onTheWire) {
  assert.equal(w.request.method, "POST");
  assert.equal(w.request.url, "https://tasks.example/sealed", "one fixed outer address, whatever the call");
  assert.deepEqual(Object.keys(w.request.headers), ["content-type"], "no header of the call, no session, no proof");
  assert.deepEqual(Object.keys(JSON.parse(w.request.body)).sort(), ["ct", "epk", "v"]);
  assert.deepEqual(Object.keys(JSON.parse(w.answerText)).sort(), ["ct", "v"], "an answer is a ciphertext and nothing else");
  for (const secret of [SECRET_TOKEN, SECRET_PATH, SECRET_BODY, "chat", "words", "what the app said", "whoami", "Bearer", "proof", "nonce", "reply", relay.aid.slice(1, 20)]) {
    const flat = w.request.body + w.answerText + JSON.stringify(w.request.headers);
    assert.ok(!flat.includes(secret) && !flat.includes(Buffer.from(secret).toString("base64url")), "the relay can read: " + secret);
  }
}
const sizes = onTheWire.map((w) => Buffer.from(JSON.parse(w.request.body).ct, "base64url").length);
assert.ok(sizes.every((n) => n === 1024 + 16), "small calls are all one size: " + sizes);

// A relay that alters, replays or swaps an answer is not believed.
for (const [name, f, re] of [
  ["alters an answer", (r) => r.text().then((t) => { const o = JSON.parse(t); o.ct = (o.ct[0] === "A" ? "B" : "A") + o.ct.slice(1); return new Response(JSON.stringify(o), { status: 200 }); }), /does not open/],
  ["answers with a refusal of its own", () => new Response("busy", { status: 503 }), /did not carry the call \(503\)/],
  ["answers with its own words", () => new Response('{"v":1,"ct":"AAAA"}', { status: 200 }), /does not open/],
]) {
  tamper = (r) => f(r);
  s = session();
  s.keep(SECRET_TOKEN);
  await assert.rejects(s.call("GET", "/session/x"), (e) => re.test(e.message), name);
}
// the answer to an earlier call, given to a later one
{
  tamper = (r) => r;
  s = session(); s.keep(SECRET_TOKEN);
  await s.call("GET", "/session/x");
  const earlier = onTheWire.at(-1).answerText;
  tamper = () => new Response(earlier, { status: 200 });
  await assert.rejects(s.call("GET", "/session/y"), /does not open/, "an old answer put to a new call");
}
// a back end whose sealing key the relay identifier did not vouch for is not spoken to
{
  const other = identity();
  const o = await sealing(other);
  assert.throws(() => readAppLink(`#aid=${app.aid}&kel=${app.log()}&rid=${relay.aid}&api=https://tasks.example`), /no sealing key/);
  const crafted = readAppLink(`#aid=${app.aid}&kel=${app.log()}&rid=${relay.aid}&api=https://tasks.example&seal=${o.statement}`);
  const c = appSession(crafted, { storage: { getItem: () => "t", setItem() {}, removeItem() {} }, fetchFn: o.wrap(backEnd), browserKey: async () => mine });
  await assert.rejects(c.call("GET", "/session/x"), /sealing key is refused/, "a sealing key from another identifier");
}
console.log("a relay reads nothing of a utility app's calls: one fixed POST, bucketed, and no altered or old answer is believed");
