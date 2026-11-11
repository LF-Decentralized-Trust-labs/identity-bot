// The signed-in half of a utility app's page (`appSession`): every call carries
// the session and a proof, every answer is checked to be the app's, an ended
// session says so in a sentence and is forgotten, and sign-out ends it.
import assert from "node:assert";
import { webcrypto } from "node:crypto";
import { ANSWER_INCEPTION, ANSWER_SIG, SessionEnded, answerText, appSession, browserKeyThumbprint, readAppLink, signInProblem } from "../dist/app.js";
import { b64u, enc, identity } from "./app-test-support.mjs";

const app = identity();
const relay = identity();
const other = identity();
const L = readAppLink(`#aid=${app.aid}&kel=${app.log()}&rid=${relay.aid}&api=https://tasks.example`);
const pair = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
const jwk = { kty: "EC", crv: "P-256", x: b64u(new Uint8Array(32).fill(1)), y: b64u(new Uint8Array(32).fill(2)) };
const mine = { privateKey: pair.privateKey, jwk, thumbprint: browserKeyThumbprint(jwk) };
const store = () => { const m = new Map(); return { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => void m.set(k, v), removeItem: (k) => void m.delete(k) }; };

const calls = [];
// A back end that answers as the app does; `signer` is whose key signs, `status` what it says.
function backEnd({ signer = relay, status = () => 200 } = {}) {
  return async (url, init) => {
    const path = new URL(String(url)).pathname;
    calls.push({ path, method: init.method, headers: init.headers, body: init.body });
    const nonce = init.headers["X-Browser-Answer-Nonce"];
    const code = status(path);
    const body = enc.encode(JSON.stringify(path === "/session/whoami" ? { pairwise_aid: "EP", browser_key: mine.thumbprint, server_time: "2030-01-01T00:00:00Z" } : { ok: true }));
    const sig = b64u(signer.sign(enc.encode(await answerText(relay.aid, nonce, code, "application/json", body))));
    return new Response(body, { status: code, headers: { "content-type": "application/json", [ANSWER_INCEPTION]: b64u(enc.encode(relay.text)), [ANSWER_SIG]: sig } });
  };
}
const open = (fetchFn, storage = store()) => appSession(L, { storage, fetchFn, browserKey: async () => mine });

// no session yet
{
  const s = open(backEnd());
  assert.equal(s.held(), null);
  await assert.rejects(s.call("GET", "/session/x"), SessionEnded, "a call with no session is a sign-in, not a request");
  assert.equal(calls.length, 0, "and goes nowhere");
}

// a session: the app's clock first, then the call, each carrying the token and a proof
{
  const s = open(backEnd());
  s.keep("tok1");
  const r = await s.call("POST", "/session/api/rank", '{"a":1}');
  assert.deepEqual(r.json(), { ok: true });
  assert.deepEqual(calls.map((c) => c.path), ["/session/whoami", "/session/api/rank"], "the app's clock is asked for first");
  for (const c of calls) {
    assert.equal(c.headers.Authorization, "Bearer tok1");
    assert.ok(c.headers["X-Browser-Proof"] && c.headers["X-Browser-Proof-Nonce"] && c.headers["X-Browser-Answer-Nonce"]);
  }
  assert.equal(calls[1].body, '{"a":1}');
  assert.ok(s.skewMs() > 1e9, "proofs are dated as the app counts, not by this device's clock");
}

// an answer the app did not sign is refused, whoever relayed it
{
  const s = open(backEnd({ signer: other }));
  s.keep("tok1");
  await assert.rejects(s.call("GET", "/session/x"), /not the app's/);
}

// a 401 ends the session in a sentence and forgets it
{
  const st = store();
  const s = open(backEnd({ status: (p) => (p === "/session/whoami" ? 200 : 401) }), st);
  s.keep("tok1");
  await assert.rejects(s.call("GET", "/session/x"), (e) => e instanceof SessionEnded && /Sign in again/.test(e.message));
  assert.equal(s.held(), null, "an ended session is not kept");
}

// sign-out tells the app, then forgets
{
  calls.length = 0;
  const s = open(backEnd());
  s.keep("tok1");
  await s.signOut();
  assert.equal(s.held(), null);
  assert.equal(calls.at(-1).path, "/session/signout");
  assert.equal(calls.at(-1).method, "POST");
  // an app that cannot be reached still leaves this browser signed out
  const down = open(async () => { throw new TypeError("Failed to fetch"); });
  down.keep("tok2");
  await down.signOut();
  assert.equal(down.held(), null);
}

// what a person is told
assert.match(signInProblem("declined"), /not accepted.*Ask the app's owner/s);
assert.match(signInProblem("expired"), /ran out of time.*Press the button/s);
assert.match(signInProblem("error", "poll 502"), /cannot be reached/);
assert.match(signInProblem("error", "poll 403"), /did not accept/);

console.log("a signed-in page makes checked calls with proofs, ends in a sentence on a 401, and signs out");
