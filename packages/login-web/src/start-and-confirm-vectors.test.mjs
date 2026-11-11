// The TypeScript start and confirm agree with test-vectors/start-and-confirm.json,
// which the Go port in packages/login-go reads too.
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { confirmLoginSession, startLoginSession } from "../dist/server.js";

const v = JSON.parse(readFileSync(new URL("../test-vectors/start-and-confirm.json", import.meta.url), "utf8"));
const answer = (r) => async () => ({
  ok: r.status >= 200 && r.status < 300, status: r.status,
  text: async () => r.text ?? JSON.stringify(r.body), json: async () => r.body,
});

for (const c of v.start) {
  let seen;
  const fetchFn = async (url, init) => { seen = { method: init.method, url: String(url), body: JSON.parse(init.body) }; return answer(c.response)(); };
  const i = c.input;
  const run = () => startLoginSession({ agentUrl: i.agent_url, assetId: i.asset_id, audience: i.audience, requestDisclosures: i.request_disclosures, browserKey: i.browser_key, frontEnd: i.front_end, fetchFn });
  if (c.expect.error_contains) await assert.rejects(run, (e) => e.message.includes(c.expect.error_contains), c.name);
  else assert.deepEqual(await run(), { sessionToken: c.expect.session_token, pointerUrl: c.expect.pointer_url, collectorSecret: c.expect.collector_secret }, c.name);
  assert.deepEqual(seen, c.request, c.name);
}

for (const c of v.confirm) {
  let seen;
  const fetchFn = async (url, init) => { seen = { url: String(url), collector_secret: init?.headers?.["X-Collector-Secret"] ?? "" }; return answer(c.response)(); };
  const i = c.input;
  const run = () => confirmLoginSession({ agentUrl: i.agent_url, assetId: i.asset_id, sessionToken: i.session_token, collectorSecret: i.collector_secret, fetchFn });
  if (c.expect.error_contains) await assert.rejects(run, (e) => e.message.includes(c.expect.error_contains), c.name);
  else {
    const r = await run();
    const want = { state: c.expect.state };
    if (c.expect.pairwise_aid) want.pairwiseAid = c.expect.pairwise_aid;
    if (c.expect.disclosures) want.disclosures = c.expect.disclosures;
    if (c.expect.member_info) want.memberInfo = { role: c.expect.member_info.role, displayName: c.expect.member_info.display_name };
    if (c.expect.browser_key) want.browserKey = c.expect.browser_key;
    if (c.expect.front_end) want.frontEnd = c.expect.front_end;
    if (c.expect.reason) want.reason = c.expect.reason;
    assert.deepEqual(JSON.parse(JSON.stringify(r)), want, c.name);
  }
  assert.deepEqual(seen, c.request, c.name);
}

{
  const claimed = new Set();
  const consume = { claim: (k) => (claimed.has(k) ? false : (claimed.add(k), true)) };
  const i = v.spending.input;
  for (const s of v.spending.steps) {
    const run = () => confirmLoginSession({ agentUrl: i.agent_url, assetId: i.asset_id, sessionToken: s.session_token, collectorSecret: i.collector_secret, fetchFn: answer({ status: 200, body: s.response }), consume });
    if (s.expect.error_contains) await assert.rejects(run, (e) => e.message.includes(s.expect.error_contains));
    else assert.equal((await run()).state, s.expect.state);
  }
}
console.log("start and confirm: every case in test-vectors/start-and-confirm.json holds in TypeScript");
