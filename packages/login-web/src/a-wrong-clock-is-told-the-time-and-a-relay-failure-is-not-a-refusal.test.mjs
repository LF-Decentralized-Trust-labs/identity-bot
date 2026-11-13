// A device whose clock is off by more than the back end takes is told the time in
// a signed, sealed answer and dates the call by it, once, for the sign-in and for
// every call after (ADR-072 Amendment 4); and a relay that fails to carry a call
// is "unreachable, try again", never a refusal to trust.
import assert from "node:assert";
import { webcrypto } from "node:crypto";
import { answerText, appFetch, appSession, AppUnreachable, browserKeyThumbprint, readAppLink } from "../dist/app.js";
import { b64u, enc, identity, logMemory, relayChain, sealing } from "./app-test-support.mjs";

const app = identity(), relay = relayChain("relay");
const sl = await sealing(relay);
const L = readAppLink(`#aid=${app.aid}&kel=${app.log()}&rid=${relay.aid}&api=https://tasks.example&seal=${sl.statement}&min=${sl.min}`);
const pair = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
const jwk = { kty: "EC", crv: "P-256", x: b64u(new Uint8Array(32).fill(1)), y: b64u(new Uint8Array(32).fill(2)) };
const mine = { privateKey: pair.privateKey, jwk, thumbprint: browserKeyThumbprint(jwk) };

// The back end's clock is three minutes ahead of this device's.
const backEndNow = () => Date.now() + 3 * 60_000;
const answered = [];
const backEnd = async (url, init) => {
  const path = new URL(String(url)).pathname;
  answered.push(path);
  const nonce = init.headers["X-Browser-Answer-Nonce"];
  const body = enc.encode(JSON.stringify(path === "/session/whoami"
    ? { pairwise_aid: "EP", browser_key: mine.thumbprint, server_time: new Date(backEndNow()).toISOString().replace(/\.\d{3}Z$/, "Z") }
    : { reply: "ok" }));
  const sig = b64u(relay.sign(enc.encode(await answerText(relay.aid, nonce, 200, "application/json", body))));
  return new Response(body, { status: 200, headers: { "content-type": "application/json", "x-keri-app-answer-log": relay.log(), "x-keri-app-answer-sig": sig } });
};
const carried = sl.wrap(backEnd, relay.aid, { now: backEndNow });

// The first call of a sign-in, dated by a clock 3 minutes behind: told the time, and retried once.
{
  const calls = [];
  const f = await appFetch(L, { fetchFn: async (u, i) => (calls.push(i), carried(u, i)), browserKey: async () => mine, logs: logMemory() });
  const before = sl.seen.length;
  const r = await f.fetchFn(L.api + "/session/whoami", { method: "GET" });
  assert.equal(r.status, 200, "the call is answered once the page has the back end's time");
  assert.equal(sl.seen.length - before, 2, "told once, then sent once more");
  const [first, second] = sl.seen.slice(-2);
  assert.ok(Math.abs(Date.parse(second.ts) - backEndNow()) < 3000, "the retry is dated by the back end's clock: " + second.ts);
  assert.ok(Math.abs(Date.parse(first.ts) - Date.now()) < 3000, "the first was dated by this device's");
}
// A signed-in call, the same.
{
  const m = new Map();
  const storage = { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => void m.set(k, v), removeItem: (k) => void m.delete(k) };
  const s = appSession(L, { storage, fetchFn: carried, browserKey: async () => mine, logs: logMemory() });
  s.keep("a-token");
  const w = await s.whoami();
  assert.ok(w.pairwise_aid === "EP");
  assert.ok(Math.abs(s.skewMs() - 3 * 60_000) < 3000, "the skew is the back end's clock's: " + s.skewMs());
  assert.equal((await s.call("GET", "/session/x")).json().reply, "ok");
}
// A clock the back end keeps calling wrong is not looped on: the person is told to set it.
{
  // a back end whose own clock moves on by an hour with every call: the retry is wrong again
  let t = 0;
  const moving = sl.wrap(backEnd, relay.aid, { now: () => Date.now() + 3 * 60_000 + 3_600_000 * t++ });
  const g = await appFetch(L, { fetchFn: moving, browserKey: async () => mine, logs: logMemory() });
  await assert.rejects(g.fetchFn(L.api + "/session/whoami", { method: "GET" }), /clock is too far/, "told twice: say so, and stop");
}
// A relay that cannot carry the call (a restart): unreachable, with a retry sentence, and no trust alarm.
{
  const down = async () => new Response("busy", { status: 503 });
  const f = await appFetch(L, { fetchFn: down, browserKey: async () => mine, logs: logMemory() });
  await assert.rejects(f.fetchFn(L.api + "/session/whoami", { method: "GET" }), (e) => e instanceof AppUnreachable && e.status === 503 && /Try again/.test(e.message) && !/trust|not the utility app/.test(e.message), "a relay's 503");
}
console.log("ok");
