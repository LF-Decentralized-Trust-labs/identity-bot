// What a utility app's page (`@identity-agent/login-web/app`) believes: a key
// log only if it derives the app's identifier, a challenge only if the app
// signed it for this page's own key, an answer only if the app signed it for
// this call, and a sign-in only through `appFetch`, which holds all three.
import assert from "node:assert";
import { webcrypto } from "node:crypto";
import { ed25519SigQb64 } from "../../login-verify/dist/browser.js";
import { b64u, enc, identity, logMemory, relayChain, sealing, nowSeconds } from "./app-test-support.mjs";
import {
  ANSWER_LOG, ANSWER_SIG, answerText, appFetch, browserKeyThumbprint, checkAppAnswer, checkAppChallenge,
  checkAppKeyLog, proofHeaders, proofText, readAppLink, serverSkew,
} from "../dist/app.js";

const app = identity();
const relay = relayChain("relay");
const refuses = (p, re, what) => assert.rejects(p, (e) => re.test(e.message), what);

// the link
const sl = await sealing(relay);
const link = `#aid=${app.aid}&kel=${app.log()}&rid=${relay.aid}&api=https://tasks.example/&seal=${sl.statement}&min=${sl.min}&iat=${nowSeconds()}`;
assert.deepEqual(readAppLink(link), { aid: app.aid, kel: app.log(), rid: relay.aid, api: "https://tasks.example", seal: sl.statement, min: sl.min });
assert.throws(() => readAppLink(`#aid=${app.aid}&kel=x&api=https://a.example&seal=s&min=${sl.min}&iat=${nowSeconds()}`), /no relay identifier/);
assert.throws(() => readAppLink(`#aid=${app.aid}&kel=x&rid=${relay.aid}&api=https://a.example&min=${sl.min}&iat=${nowSeconds()}`), /no sealing key/);
assert.throws(() => readAppLink(`#aid=${app.aid}&kel=x&rid=${relay.aid}&api=http://evil.example&seal=s&min=${sl.min}&iat=${nowSeconds()}`), /no back end/);
assert.throws(() => readAppLink(`#aid=${app.aid}&kel=x&rid=${relay.aid}&api=https://a.example&seal=s`), /no latest key log event/);
assert.doesNotThrow(() => readAppLink(`#aid=${app.aid}&kel=x&rid=${relay.aid}&api=http://127.0.0.1:9&seal=s&min=${sl.min}&iat=${nowSeconds()}`));

// the key log
assert.deepEqual(await checkAppKeyLog(app.aid, app.log()), app.key);
await refuses(checkAppKeyLog(relay.aid, app.log()), /not the utility app's identifier/, "another identifier's log");
await refuses(checkAppKeyLog(app.aid, app.log({ cesr_signatures: [ed25519SigQb64(new Uint8Array(64))] })), /not signed by the key/, "a wrong signature");
await refuses(checkAppKeyLog(app.aid, b64u(JSON.stringify({ raw_events_b64: [], cesr_signatures: [], extra: 1 }))), /fields it should not/, "extra fields");
{ const forged = identity(); // an event naming the app's identifier but not derived from it
  const text = forged.text.replaceAll(forged.aid, app.aid);
  const l = b64u(JSON.stringify({ raw_events_b64: [Buffer.from(text).toString("base64")], cesr_signatures: [ed25519SigQb64(new Uint8Array(forged.sign(enc.encode(text))))] }));
  await refuses(checkAppKeyLog(app.aid, l), /does not derive the identifier/, "a self-signed event under another's identifier"); }

// the challenge
const thumb = browserKeyThumbprint({ x: b64u(new Uint8Array(32).fill(1)), y: b64u(new Uint8Array(32).fill(2)) });
const challenge = (over = {}, id = app) => {
  const body = JSON.stringify({ v: "ASK1", t: 1, site_aid: app.aid, browser_key: thumb, expiry: new Date(Date.now() + 600_000).toISOString(), session_token: "tok", ...over });
  return { aid: app.aid, key: app.key, body, sig: ed25519SigQb64(new Uint8Array(id.sign(enc.encode(body)))), pointer: "https://ia.example/i/tok", ownThumbprint: thumb };
};
assert.equal((await checkAppChallenge(challenge())).session_token, "tok");
assert.equal((await checkAppChallenge(challenge({ front_end: "browser" }))).front_end, "browser");
await refuses(checkAppChallenge(challenge({ front_end: "installed_app" })), /another kind of front end/, "an installed-app challenge");
await refuses(checkAppChallenge(challenge({ browser_key: "x".repeat(43) })), /this page's own key/, "another browser's key");
await refuses(checkAppChallenge(challenge({ site_aid: relay.aid })), /another utility app/, "another app's challenge");
await refuses(checkAppChallenge(challenge({ expiry: new Date(Date.now() - 1000).toISOString() })), /lapsed/, "a lapsed challenge");
await refuses(checkAppChallenge(challenge({}, relay)), /not signed by the utility app/, "signed by another key");
await refuses(checkAppChallenge({ ...challenge(), pointer: "https://ia.example/i/other" }), /not this challenge's/, "another challenge's code");
await refuses(checkAppChallenge({ ...challenge(), pointer: "http://ia.example/i/tok" }), /not this challenge's/, "a code that is not https");

// an answer
const answer = async (over = {}) => {
  const a = { rid: relay.aid, nonce: "n1", status: 200, contentType: "application/json", body: enc.encode('{"ok":true}'), ...over };
  const sig = b64u(relay.sign(enc.encode(await answerText(relay.aid, "n1", 200, "application/json", enc.encode('{"ok":true}')))));
  return { ...a, log: relay.log(), sig };
};
await checkAppAnswer(await answer());
await refuses(checkAppAnswer(await answer({ nonce: "n2" })), /does not hold for this call/, "an answer to another call");
await refuses(checkAppAnswer(await answer({ body: enc.encode('{"ok":false}') })), /does not hold for this call/, "a changed body");
await refuses(checkAppAnswer(await answer({ status: 500 })), /does not hold for this call/, "a changed status");
await refuses(checkAppAnswer({ ...(await answer()), sig: null }), /not signed/, "an unsigned answer");
await refuses(checkAppAnswer({ ...(await answer()), rid: app.aid }), /not the identifier the link names/, "another identifier");

// a proof, and the app's clock
const pair = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
const h = await proofHeaders(pair.privateKey, "GET", "/signin/session/abc?x=1", "abc", "", 5000);
assert.ok(await webcrypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pair.publicKey, Buffer.from(h["X-Browser-Proof"], "base64url"),
  enc.encode(await proofText("GET", "/signin/session/abc?x=1", h["X-Browser-Proof-Time"], h["X-Browser-Proof-Nonce"], "abc", ""))));
assert.equal(serverSkew("2026-11-11T12:00:10Z", Date.parse("2026-11-11T12:00:00Z")), 10_000);
assert.throws(() => serverSkew(undefined), /no time/);

// appFetch: the whole of it, against a back end that answers as the app does
const jwk = { kty: "EC", crv: "P-256", x: b64u(new Uint8Array(32).fill(1)), y: b64u(new Uint8Array(32).fill(2)) };
const mine = { privateKey: pair.privateKey, jwk, thumbprint: thumb };
const calls = [];
function backEnd({ lie = false } = {}) {
  return async (url, init) => {
    calls.push({ url: String(url), method: init.method, headers: init.headers, body: init.body });
    const nonce = init.headers["X-Browser-Answer-Nonce"];
    const isStart = init.method === "POST";
    const body = enc.encode(JSON.stringify(isStart
      ? (() => { const c = challenge(lie ? { site_aid: relay.aid } : {}); return { session_token: "sid1", relay_or_qr_url: c.pointer, canonical_body: c.body, sig: c.sig, server_time: new Date().toISOString().replace(/\.\d{3}Z$/, "Z") }; })()
      : { state: "connecting" }));
    const sig = b64u(relay.sign(enc.encode(await answerText(relay.aid, nonce, 200, "application/json", body))));
    return new Response(body, { status: 200, headers: { "content-type": "application/json", [ANSWER_LOG]: relay.log(), [ANSWER_SIG]: sig } });
  };
}
const L = readAppLink(link);
const a = await appFetch(L, { fetchFn: sl.wrap(backEnd()), browserKey: async () => mine, logs: logMemory() });
assert.equal(a.sessionEndpoint, "https://tasks.example/signin/session");
assert.equal(a.browserKey, thumb);
const started = await (await a.fetchFn(a.sessionEndpoint, { method: "POST", body: JSON.stringify({ browserKey: thumb }) })).json();
assert.equal(started.session_token, "sid1");
assert.deepEqual(JSON.parse(calls[0].body).jwk, jwk, "the start carries this browser's public key");
const polled = await (await a.fetchFn(`${a.sessionEndpoint}/sid1`, {})).json();
assert.equal(polled.state, "connecting");
assert.ok(calls[1].headers["X-Browser-Proof"] && calls[1].headers["X-Browser-Proof-Nonce"], "a poll carries a proof");
const liar = await appFetch(L, { fetchFn: sl.wrap(backEnd({ lie: true })), browserKey: async () => mine, logs: logMemory() });
await refuses(liar.fetchFn(liar.sessionEndpoint, { method: "POST", body: "{}" }), /another utility app/, "a back end that hands over another app's challenge");
const unsigned = await appFetch(L, { fetchFn: sl.wrap(async () => new Response("{}", { status: 200 })), browserKey: async () => mine, logs: logMemory() });
await refuses(unsigned.fetchFn(unsigned.sessionEndpoint, { method: "POST", body: "{}" }), /not signed/, "an answer nobody signed");
await refuses(appFetch({ ...L, kel: app.log({ cesr_signatures: [ed25519SigQb64(new Uint8Array(64))] }) }, { browserKey: async () => mine }), /key log is refused/, "a link whose key log is not the app's");

// the app's key rotates: the page goes by the key the log names now, remembers the longest log, and
// never believes the key the log has left, shown with its own shorter log.
{
  const rot = relayChain("relay", 2); // the same identifier as `relay`? no: a chain of its own, rotated twice
  const ans = async (chain, upTo, signerIndex, nonce = "n1") => {
    const body = enc.encode('{"ok":true}');
    const sig = b64u(chain.keys[signerIndex].sign(enc.encode(await answerText(chain.aid, nonce, 200, "application/json", body))));
    return { rid: chain.aid, nonce, status: 200, contentType: "application/json", body, log: chain.log(upTo), sig };
  };
  const mem = logMemory();
  const seen = async (a) => mem.set(a.rid, (await checkAppAnswer({ ...a, known: mem.get(a.rid) })).log);
  await seen(await ans(rot, 1, 0)); // the inception's key, before any rotation
  await seen(await ans(rot, 3, 2)); // after two rotations, the current key
  assert.equal(mem.get(rot.aid), rot.log(3));
  await refuses(checkAppAnswer({ ...(await ans(rot, 1, 0)), known: mem.get(rot.aid) }), /behind or apart/, "the first machine's key with its own short log, after the rotation was seen");
  await refuses(checkAppAnswer({ ...(await ans(rot, 2, 1)), known: mem.get(rot.aid) }), /behind or apart/, "an intermediate roll-back");
  await refuses(checkAppAnswer({ ...(await ans(rot, 3, 0)), known: mem.get(rot.aid) }), /does not hold for this call/, "the old key under the current log");
  // a page that has seen nothing still reads the log from its inception, so a log that does not verify never gets in
  const forkedKeys = relayChain("relay-fork", 2);
  await refuses(checkAppAnswer({ ...(await ans(forkedKeys, 3, 2)), rid: rot.aid }), /not the identifier the link names/, "another identifier's log under this one's name");
}

console.log("a utility app's page believes only its own app: key log, challenge, answers, and the sign-in through appFetch");
