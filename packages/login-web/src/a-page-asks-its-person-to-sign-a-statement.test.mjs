// `session.signStatement` (ADR-080): the signed-in page asks the person's own Identity Agent to sign a
// statement and is handed {signature, signer_aid, kel_sn}. Every state of the wait is shown in plain words,
// a declined or expired request is told so and can be asked again, and an answer that is not whole
// sends nothing.
import assert from "node:assert";
import { webcrypto } from "node:crypto";
import { ANSWER_LOG, ANSWER_SIG, SessionEnded, StatementNotSigned, answerText, appSession, browserKeyThumbprint, readAppLink, statementWords } from "../dist/app.js";
import { b64u, enc, identity, logMemory, relayChain, sealing, nowSeconds } from "./app-test-support.mjs";

const app = identity();
const relay = relayChain("relay");
const sl = await sealing(relay);
const L = readAppLink(`#aid=${app.aid}&kel=${app.log()}&rid=${relay.aid}&api=https://tasks.example&seal=${sl.statement}&min=${sl.min}&iat=${nowSeconds()}`);
const pair = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
const jwk = { kty: "EC", crv: "P-256", x: b64u(new Uint8Array(32).fill(1)), y: b64u(new Uint8Array(32).fill(2)) };
const mine = { privateKey: pair.privateKey, jwk, thumbprint: browserKeyThumbprint(jwk) };
const store = () => { const m = new Map(); return { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => void m.set(k, v), removeItem: (k) => void m.delete(k) }; };

// A back end that answers as the app does. `route(method, path, body)` gives {status, json}.
function backEnd(route) {
  const calls = [];
  const fn = async (url, init) => {
    const path = new URL(String(url)).pathname;
    const nonce = init.headers["X-Browser-Answer-Nonce"];
    const out = path === "/session/whoami"
      ? { status: 200, json: { pairwise_aid: "EP", browser_key: mine.thumbprint, server_time: "2030-01-01T00:00:00Z" } }
      : route(init.method, path, init.body, calls);
    if (path !== "/session/whoami") calls.push({ method: init.method, path, body: init.body });
    const body = enc.encode(JSON.stringify(out.json));
    const sig = b64u(relay.sign(enc.encode(await answerText(relay.aid, nonce, out.status, "application/json", body))));
    return new Response(body, { status: out.status, headers: { "content-type": "application/json", [ANSWER_LOG]: relay.log(), [ANSWER_SIG]: sig } });
  };
  fn.calls = calls;
  return fn;
}
// A screen that records every view, and presses buttons on cue.
function screen() {
  const views = [];
  let actions;
  return { views, press: (a) => actions[a](), closed: 0, show(v, a) { views.push(v); actions = a; }, close() { this.closed++; } };
}
const open = (fn, presenter, extra = {}) => {
  const s = appSession(L, { storage: store(), fetchFn: sl.wrap(fn), browserKey: async () => mine, logs: logMemory(), statementPresenter: presenter, sleep: async () => {}, ...extra });
  s.keep("tok1");
  return s;
};
const TRIPLE = { signature: "AA" + "x".repeat(86), signer_aid: "EOwner", kel_sn: 5 };
const statement = "grape-decision-approval/1\ndecision=7";

// the whole way: pointer, waiting, scanned, signed; resolves with exactly the three fields
{
  let polls = 0;
  const fn = backEnd((m, p) => {
    if (m === "POST" && p === "/session/statement") return { status: 200, json: { id: "s1", pointer: "https://org.example/i/abc" } };
    polls++;
    return { status: 200, json: polls === 1 ? { state: "pending" } : polls === 2 ? { state: "scanned" } : { state: "verified", ...TRIPLE } };
  });
  const sc = screen();
  const got = await open(fn, sc).signStatement(statement, { title: "Use the queue" });
  assert.deepEqual(got, TRIPLE);
  assert.deepEqual(sc.views.map((v) => v.state), ["pointer", "waiting", "scanned", "signed"]);
  assert.equal(sc.views[0].pointer, "https://org.example/i/abc");
  assert.equal(sc.views[0].statement, statement, "the statement asked is shown on the page too, to compare with the device");
  assert.equal(sc.closed, 1);
  assert.deepEqual(JSON.parse(fn.calls[0].body), { statement, title: "Use the queue" });
  for (const v of sc.views) assert.ok(statementWords(v).title.length > 0 && statementWords(v).body.length > 0, "no state is a bare spinner");
}

// the words: every one says the signing is on the person's own device
{
  const pointer = "https://x/i/1";
  const w = (state) => statementWords({ state, pointer, statement, reason: "why" });
  assert.match(w("pointer").title, /Sign on your own device\./);
  assert.match(w("waiting").body, /Nothing is signed until you approve on it/);
  assert.match(w("scanned").title, /Your device has the request/);
  assert.match(w("signed").title, /Signed on your device/);
  assert.match(w("declined").title, /declined on your device/);
  assert.match(w("declined").body, /Nothing was signed/);
  assert.match(w("expired").title, /expired before it was signed/);
  assert.equal(w("expired").labels.again, "Start again");
  assert.equal(w("declined").labels.again, "Try again");
  assert.equal(w("error").body, "why");
}

// declined: said so, offers Try again, which asks for a new code that can be signed
{
  let started = 0;
  const fn = backEnd((m, p) => {
    if (m === "POST") return { status: 200, json: { id: "s" + ++started, pointer: "https://org.example/i/" + started } };
    return { status: 200, json: p.endsWith("s1") ? { state: "declined" } : { state: "verified", ...TRIPLE } };
  });
  const sc = screen();
  const s = open(fn, sc, { sleep: async () => { if (sc.views.at(-1)?.state === "declined") sc.press("again"); } });
  assert.deepEqual(await s.signStatement(statement), TRIPLE);
  assert.equal(started, 2, "Try again made a new request");
  assert.deepEqual(sc.views.map((v) => v.state), ["pointer", "declined", "pointer", "signed"]);
}

// declined and then closed: nothing signed, rejected with the reason
{
  const fn = backEnd((m) => (m === "POST" ? { status: 200, json: { id: "s1", pointer: "p" } } : { status: 200, json: { state: "declined" } }));
  const sc = screen();
  const s = open(fn, sc, { sleep: async () => { if (sc.views.at(-1)?.state === "declined") sc.press("cancel"); } });
  await assert.rejects(s.signStatement(statement), (e) => e instanceof StatementNotSigned && e.reason === "cancelled" && /Nothing was signed/.test(e.message));
  assert.equal(sc.closed, 1);
}

// expired: told so; Start again asks for a new code and the new one can be signed
{
  let started = 0;
  const fn = backEnd((m, p) => {
    if (m === "POST") return { status: 200, json: { id: "s" + ++started, pointer: "https://org.example/i/" + started } };
    return { status: 200, json: p.endsWith("s1") ? { state: "expired" } : { state: "verified", ...TRIPLE } };
  });
  const sc = screen();
  const s = open(fn, sc, { sleep: async () => { if (sc.views.at(-1)?.state === "expired") sc.press("again"); } });
  assert.deepEqual(await s.signStatement(statement), TRIPLE);
  assert.equal(started, 2, "Start again made a new request");
  assert.deepEqual(sc.views.map((v) => v.state), ["pointer", "expired", "pointer", "signed"]);
  assert.equal(sc.views[2].pointer, "https://org.example/i/2");
}

// the Identity Agent that asked forgot it (404): said as an expired request is
{
  const fn = backEnd((m) => (m === "POST" ? { status: 200, json: { id: "s1", pointer: "p" } } : { status: 404, json: { error: "no such statement" } }));
  const sc = screen();
  const s = open(fn, sc, { sleep: async () => { if (sc.views.at(-1)?.state === "expired") sc.press("cancel"); } });
  await assert.rejects(s.signStatement(statement), (e) => e instanceof StatementNotSigned && e.reason === "expired");
}

// an answer that is not whole sends nothing: each of the three fields is needed, kel_sn is an integer
for (const bad of [{ ...TRIPLE, signature: undefined }, { ...TRIPLE, signer_aid: "" }, { ...TRIPLE, kel_sn: "5" }, { ...TRIPLE, kel_sn: 5.5 }, { ...TRIPLE, kel_sn: -1 }, { ...TRIPLE, kel_sn: undefined }]) {
  const fn = backEnd((m) => (m === "POST" ? { status: 200, json: { id: "s1", pointer: "p" } } : { status: 200, json: { state: "verified", ...bad } }));
  const sc = screen();
  await assert.rejects(open(fn, sc).signStatement(statement), (e) => e instanceof StatementNotSigned && e.reason === "error" && /not whole/.test(e.message), JSON.stringify(bad));
  assert.equal(sc.views.at(-1).state, "error");
}

// the app will not start it: the reason is a sentence, not a status code
for (const [status, json, want] of [[403, {}, /not been given the right/], [400, { error: "the statement has a character that cannot be shown as it is (U+202E)" }, /U\+202E/], [503, {}, /could not be reached/]]) {
  const fn = backEnd(() => ({ status, json }));
  const sc = screen();
  await assert.rejects(open(fn, sc).signStatement(statement), (e) => e instanceof StatementNotSigned && e.reason === "refused" && want.test(e.message) && !/\b(403|400|503)\b/.test(e.message));
  assert.equal(sc.views.at(-1).state, "error");
}

// an ended session closes the screen and says so, as every call does
{
  const fn = backEnd((m) => (m === "POST" ? { status: 401, json: {} } : { status: 200, json: {} }));
  const sc = screen();
  await assert.rejects(open(fn, sc).signStatement(statement), SessionEnded);
  assert.equal(sc.closed, 1);
}

// no session: nothing is asked
{
  const fn = backEnd(() => ({ status: 200, json: {} }));
  const s = appSession(L, { storage: store(), fetchFn: sl.wrap(fn), browserKey: async () => mine, logs: logMemory() });
  await assert.rejects(s.signStatement(statement), SessionEnded);
  assert.equal(fn.calls.length, 0);
}

console.log("a page asks its person to sign a statement");
