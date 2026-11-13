// A routine rotation of the relay identifier moves the sealing key, and a page holding the
// old one is not stranded: the back end says the key it was sealed to has moved on, the page
// fetches the statement now in force, checks it as it checks a link's, seals the same call
// again, once, and the call's text is sent as it was (ADR-072 Amendment 4). Only when that
// cannot be done is the person told the link is out of date.
import assert from "node:assert";
import { webcrypto } from "node:crypto";
import { answerText, appFetch, appSession, AppUnreachable, browserKeyThumbprint, LinkOutOfDate, readAppLink } from "../dist/app.js";
import { openRequest, SEAL_PATH, SEAL_STATEMENT_PATH } from "../dist/seal.js";
import { b64u, enc, identity, keyFor, logMemory, nowSeconds, relayChain, sealing } from "./app-test-support.mjs";

const app = identity();
const before = relayChain("rot"); // the log the page's link carries
const after = relayChain("rot", 1); // the same identifier after one rotation
assert.equal(after.events[0].said, before.events[0].said, "the rotated log carries on from the earlier one");
const old = await sealing(before);
const fresh = await sealing(after);
const L = readAppLink(`#aid=${app.aid}&kel=${app.log()}&rid=${before.aid}&api=https://tasks.example&seal=${old.statement}&min=${old.min}&iat=${nowSeconds()}`);
const pair = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
const jwk = { kty: "EC", crv: "P-256", x: b64u(new Uint8Array(32).fill(1)), y: b64u(new Uint8Array(32).fill(2)) };
const mine = { privateKey: pair.privateKey, jwk, thumbprint: browserKeyThumbprint(jwk) };

/** The back end after the rotation: it opens only calls sealed to `current`, says "sealing key" to others, and
 *  serves `statement` at the statement path. `bodies` is what its routes were sent. */
function backEnd({ current = fresh, statement = fresh.statement, statementStatus = 200, alwaysMoved = false, notAccepted = false } = {}) {
  const log = { bodies: [], statementGets: 0, posts: 0 };
  const routes = async (url, init) => {
    const path = new URL(String(url)).pathname;
    const nonce = init.headers["X-Browser-Answer-Nonce"];
    log.bodies.push(init.body);
    const body = enc.encode(JSON.stringify(path === "/session/whoami" ? { pairwise_aid: "EP", browser_key: mine.thumbprint, server_time: new Date().toISOString().replace(/\.\d{3}Z$/, "Z") } : { reply: "ok" }));
    const sig = b64u(after.sign(enc.encode(await answerText(after.aid, nonce, 200, "application/json", body))));
    return new Response(body, { status: 200, headers: { "content-type": "application/json", "x-keri-app-answer-log": after.log(), "x-keri-app-answer-sig": sig } });
  };
  const carried = current.wrap(routes, after.aid);
  const fetchFn = async (url, init = {}) => {
    const path = new URL(String(url)).pathname;
    if (path === SEAL_STATEMENT_PATH && (init.method ?? "GET") === "GET") {
      log.statementGets++;
      return new Response(statementStatus === 200 ? statement : "down", { status: statementStatus });
    }
    assert.equal(path, SEAL_PATH);
    log.posts++;
    if (notAccepted) return new Response('{"error":"not accepted"}', { status: 400 });
    try {
      await openRequest(after.aid, current.pair, init.body);
    } catch {
      return new Response('{"error":"sealing key"}', { status: 400, headers: { "content-type": "application/json" } });
    }
    if (alwaysMoved) return new Response('{"error":"sealing key"}', { status: 400 });
    return carried(url, init);
  };
  return { fetchFn, log };
}
const store = () => {
  const m = new Map();
  return { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => void m.set(k, v), removeItem: (k) => void m.delete(k) };
};
const session = (b, extra = {}) => appSession(L, { storage: store(), fetchFn: b.fetchFn, browserKey: async () => mine, logs: logMemory(), ...extra });

// A signed-in page that held the old key: the call is sealed again to the new one and goes through, once, with its text.
{
  const b = backEnd();
  const s = session(b);
  s.keep("a-token");
  const r = await s.call("POST", "/api/mcp/agents/a/conversations", JSON.stringify({ text: "the message that was being sent" }));
  assert.equal(r.json().reply, "ok", "the call that crossed a rotation is answered");
  assert.equal(b.log.statementGets, 1, "the statement now in force was fetched once");
  assert.ok(b.log.posts >= 2, "sealed once to the old key, then to the new");
  assert.deepEqual(JSON.parse(b.log.bodies.at(-1)), { text: "the message that was being sent" }, "what the person was sending is sent as it was");
  // and the next call is sealed to the new key straight away
  await s.call("GET", "/session/x");
  assert.equal(b.log.statementGets, 1, "the key is kept: no second fetch");
}
// The sign-in call, the same.
{
  const b = backEnd();
  const f = await appFetch(L, { fetchFn: b.fetchFn, browserKey: async () => mine, logs: logMemory() });
  const r = await f.fetchFn(L.api + "/session/whoami", { method: "GET" });
  assert.equal(r.status, 200);
  assert.equal(b.log.statementGets, 1);
}
// A statement the relay identifier's current key did not sign is not taken: the link is out of date.
{
  const forged = (await sealing(after)).statement.replace(/^/, "");
  const other = relayChain("another", 1);
  const bad = (await sealing(other)).statement; // another identifier's
  for (const [name, statement] of [["another identifier's", bad], ["not a statement", "AAAA"]]) {
    const b = backEnd({ statement });
    const s = session(b);
    s.keep("t");
    await assert.rejects(s.call("GET", "/session/x"), (e) => e instanceof LinkOutOfDate && /out of date/.test(e.message) && /Identity Agent/.test(e.message), name);
    assert.equal(b.log.posts, 1, "nothing is sent on a key that was not shown: " + name);
  }
  assert.ok(forged);
}
// A statement from before the link's own minimum is not taken either.
{
  const newer = readAppLink(`#aid=${app.aid}&kel=${app.log()}&rid=${after.aid}&api=https://tasks.example&seal=${fresh.statement}&min=${fresh.min}&iat=${nowSeconds()}`);
  const b = backEnd({ current: old, statement: old.statement }); // a back end behind the link: serves the shorter log
  const stale = await sealing(after);
  const s = appSession(newer, { storage: store(), fetchFn: async (u, i) => (new URL(String(u)).pathname === SEAL_PATH ? new Response('{"error":"sealing key"}', { status: 400 }) : b.fetchFn(u, i)), browserKey: async () => mine, logs: logMemory() });
  s.keep("t");
  await assert.rejects(s.call("GET", "/session/x"), (e) => e instanceof LinkOutOfDate);
  assert.ok(stale);
}
// The key said to have moved on a second time after the one retry: the link is out of date, and the page does not loop.
{
  const b = backEnd({ alwaysMoved: true });
  const s = session(b);
  s.keep("t");
  await assert.rejects(s.call("GET", "/session/x"), (e) => e instanceof LinkOutOfDate);
  assert.equal(b.log.posts, 2, "one retry, no more");
  assert.equal(b.log.statementGets, 1);
}
// The relay failing to give the statement is "unreachable, try again", never "out of date".
{
  const b = backEnd({ statementStatus: 503 });
  const s = session(b);
  s.keep("t");
  await assert.rejects(s.call("GET", "/session/x"), (e) => e instanceof AppUnreachable && !(e instanceof LinkOutOfDate));
}
// Any other refusal is not a moved key: no statement is fetched.
{
  const b = backEnd({ notAccepted: true });
  const s = session(b);
  s.keep("t");
  await assert.rejects(s.call("GET", "/session/x"), (e) => e instanceof AppUnreachable);
  assert.equal(b.log.statementGets, 0);
}
// A key the page already holds is not a rotation: the statement is the same key, so try-again, not out of date.
{
  const same = backEnd({ current: old, statement: old.statement });
  const s = appSession(L, { storage: store(), fetchFn: async (u, i) => (new URL(String(u)).pathname === SEAL_PATH ? new Response('{"error":"sealing key"}', { status: 400 }) : same.fetchFn(u, i)), browserKey: async () => mine, logs: logMemory() });
  s.keep("t");
  await assert.rejects(s.call("GET", "/session/x"), (e) => e instanceof AppUnreachable && !(e instanceof LinkOutOfDate));
}
console.log("ok: a rotation does not strand a page");
