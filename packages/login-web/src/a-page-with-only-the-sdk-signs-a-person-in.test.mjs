// A page with only the login SDK (no back end of its own) signs a person in
// through the website owner's Identity Agent on its public login routes, and
// checks the assertion it was handed in the page. Here the Identity Agent is
// the stand-in (login-verify's an-identity-agent-stand-in.mjs); the real core
// answers the same wire in a_page_with_only_the_sdk_signs_a_person_in_test.go.
import assert from "node:assert";
import { anIdentityAgentStandIn } from "../../login-verify/src/an-identity-agent-stand-in.mjs";
import { inMemoryConsumedNonces } from "../../login-verify/dist/browser.js";
import { startPageSession } from "../dist/page.js";
import { aPageWithOnlyTheSdk } from "./a-page-with-only-the-sdk.mjs";

const ORIGIN = "https://portal.example";
const ia = await anIdentityAgentStandIn();
const alice = await ia.aPerson("Alice");
const aPage = (extra = {}) => aPageWithOnlyTheSdk({ agentUrl: ia.url, assetId: "the-website", origin: ORIGIN, ...extra });

// The store is the back end's: claim(key, keepUntilMs). Record what it is asked.
const claims = [];
const spent = inMemoryConsumedNonces();
const consume = { claim: (k, until) => (claims.push({ k, until }), spent.claim(k, until)), release: (k) => spent.release(k) };

// 1. A member signs in. Nobody has answered yet: nothing is signed in.
const page = aPage({ consume, expectedSiteAid: ia.siteAid });
const started = await page.start();
assert.ok(started.pointer_url.endsWith(`/i/${started.session_token}`), "the page is given a pointer to show");
assert.equal((await page.poll()).state, "pending");
assert.equal(ia.sessions.get(started.session_token).audience, ORIGIN, "the audience is the page's origin, which the page did not name");
await ia.answer(started.session_token, alice);
const got = await page.poll();
assert.equal(got.state, "signed-in", JSON.stringify(got));
assert.equal(got.pairwise_aid, alice.aid);
assert.equal(got.claimed_by_agent, alice.aid, "what the agent said and what the page checked agree");
assert.equal(ia.asked.at(-1).key_log, alice.keyLog, "the person's own key log is what the Identity Agent was asked about");

// 2. The back end's rule, not a second one: the assertion is claimed with a
// keep-until time, and presented again it is refused as already used.
assert.equal(claims.length, 1);
assert.ok(claims[0].until > Date.now(), "the claim carries a keep-until time");
const again = await page.checkAgain();
assert.equal(again.valid, false);
assert.match(again.reason, /already used/);
assert.equal(claims.length, 2, "the second presentation went through the same store");
// The result is handed over once: reading the sign-in again yields no identity.
assert.equal((await page.poll()).state, "withheld");

// 3. Another sign-in by the same person is another assertion and signs in; a
// store that cannot say refuses, rather than accepting what it cannot record.
const lastToken = () => [...ia.sessions.keys()].at(-1);
const third = aPage({ consume });
await third.start();
await ia.answer(lastToken(), alice);
assert.equal((await third.poll()).state, "signed-in");
const broken = aPage({ consume: { claim: () => { throw new Error("the replay store is full"); } } });
await broken.start();
await ia.answer(lastToken(), alice);
const refusedForStore = await broken.poll();
assert.equal(refusedForStore.state, "refused");
assert.match(refusedForStore.reason, /replay store unavailable/);

// 4. An assertion for another page is refused: the audience is the page's own origin.
const p4 = aPage({ consume: inMemoryConsumedNonces() });
const s4 = await p4.start();
ia.sessions.get(s4.session_token).audience = "https://other.example";
await ia.answer(s4.session_token, alice);
const wrongAudience = await p4.poll();
assert.equal(wrongAudience.state, "refused");
assert.match(wrongAudience.reason, /audience mismatch/);

// 5. A key log that establishes no key for the person signs nobody in.
const mallory = { ...alice, ...(await ia.aPerson("Mallory", { established: false })) , aid: alice.aid };
const p5 = aPage({ consume: inMemoryConsumedNonces() });
const s5 = await p5.start();
await ia.answer(s5.session_token, mallory);
const forged = await p5.poll();
assert.equal(forged.state, "refused");
assert.match(forged.reason, /establishes no key/);

// 6. A page that pins its site refuses an assertion for any other.
const p6 = aPage({ consume: inMemoryConsumedNonces(), expectedSiteAid: "EAnotherSite000000000000000000000000000000" });
const s6 = await p6.start();
await ia.answer(s6.session_token, alice);
const otherSite = await p6.poll();
assert.equal(otherSite.state, "refused");
assert.match(otherSite.reason, /site mismatch/);

// 7. A stale assertion is refused; a page may not claim another origin as its audience.
const p7 = aPage({ consume: inMemoryConsumedNonces() });
const s7 = await p7.start();
await ia.answer(s7.session_token, { ...alice, dt: new Date(Date.now() - 3600_000).toISOString().replace(/\.\d{3}Z$/, "Z") });
assert.match((await p7.poll()).reason, /freshness/);
await assert.rejects(
  () => startPageSession({
    sessionEndpoint: `${ia.url}/api/login/session/the-website`,
    body: { audience: "https://victim.example" },
    fetchFn: (u, i) => fetch(u, { ...i, headers: { ...i.headers, Origin: ORIGIN } }),
  }),
  /400/,
);

// 8. A person who declines signs nobody in.
const p8 = aPage({ consume: inMemoryConsumedNonces() });
const s8 = await p8.start();
ia.decline(s8.session_token);
assert.equal((await p8.poll()).state, "declined");

await ia.close();
console.log("a page with only the SDK signs a person in, checks the assertion in the page, and refuses a replay by the back end's rule");
