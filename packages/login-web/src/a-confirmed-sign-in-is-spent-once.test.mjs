// A site that issues its own session on "verified" must not do so twice for one
// sign-in, and starting a sign-in from the server must hand back the secret.
import assert from "node:assert";
import { confirmLoginSession, startLoginSession } from "../dist/server.js";

const claimed = new Set();
const consume = { claim: (k) => (claimed.has(k) ? false : (claimed.add(k), true)) };
const verified = async () => ({
  ok: true,
  json: async () => ({ state: "verified", app_session_token: "EPairwise" }),
});
const opts = { agentUrl: "https://ia.example", assetId: "the-portal", sessionToken: "tok", collectorSecret: "s", fetchFn: verified, consume };

assert.equal((await confirmLoginSession(opts)).state, "verified");
await assert.rejects(() => confirmLoginSession(opts), /already been used/);
// Another sign-in is unaffected, and a pending one spends nothing.
assert.equal((await confirmLoginSession({ ...opts, sessionToken: "tok2" })).state, "verified");
const pending = { ...opts, sessionToken: "tok3", fetchFn: async () => ({ ok: true, json: async () => ({ state: "connecting" }) }) };
assert.equal((await confirmLoginSession(pending)).state, "pending");
assert.equal((await confirmLoginSession({ ...pending, fetchFn: verified })).state, "verified");

// Every claim carries the time it may be forgotten at.
const untils = [];
const recording = { claim: (k, until) => (untils.push(until), true) };
const t0 = Date.now();
await confirmLoginSession({ ...opts, sessionToken: "t4", consume: recording });
await confirmLoginSession({ ...opts, sessionToken: "t5", consume: recording, consumeForSeconds: 60 });
assert.ok(untils[0] >= t0 + 3600_000 && untils[0] <= Date.now() + 3600_000, "default window is an hour");
assert.ok(untils[1] >= t0 + 60_000 && untils[1] <= Date.now() + 60_000, "the window can be set");

// Starting: the request names the asset and the site's audience; the secret comes back.
let seen;
const s = await startLoginSession({
  agentUrl: "https://ia.example/", assetId: "the portal", audience: "https://portal.example", requestDisclosures: ["display_name"],
  fetchFn: async (url, init) => {
    seen = { url: String(url), body: JSON.parse(init.body) };
    return { ok: true, json: async () => ({ session_token: "t", relay_or_qr_url: "https://ia.example/i/t", collector_secret: "sec" }) };
  },
});
assert.equal(seen.url, "https://ia.example/api/login/session/the%20portal");
assert.equal(seen.body.audience, "https://portal.example");
assert.deepEqual(s, { sessionToken: "t", pointerUrl: "https://ia.example/i/t", collectorSecret: "sec" });
await assert.rejects(() => startLoginSession({ agentUrl: "https://ia.example", assetId: "x", audience: "a", fetchFn: async () => ({ ok: false, status: 404, text: async () => "asset not found" }) }), /404: asset not found/);

console.log("confirm: a verified sign-in is spent once; start hands the server its secret");
