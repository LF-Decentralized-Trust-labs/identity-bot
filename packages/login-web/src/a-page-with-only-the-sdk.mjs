// ILLUSTRATIVE, for the end-to-end tests; not a model to copy whole. A real
// page is shown to the person by a browser: it renders the pointer as a QR code
// (SignInButton does), and would not print the identity it was handed.
//
// A third party's web page, with the login SDK and nothing else behind it: no
// back end, no key. It starts a sign-in on the website asset its owner's
// Identity Agent holds, shows the person the pointer, reads the answer with the
// secret only it was given, and checks the assertion it was handed in the page.
// It uses what SignInButton uses (startPageSession, readPageSession) and
// `checkSignInInPage`, and sends the Origin a browser would: a page cannot
// choose it, and the Identity Agent takes the audience from it.
//
// Used as a module by a-page-with-only-the-sdk-signs-a-person-in.test.mjs, and driven line by line
// over stdin by the Identity Agent's own end-to-end test
// (a_page_with_only_the_sdk_signs_a_person_in_test.go):
//   IA_URL=https://ia.example ASSET_ID=the-website ORIGIN=https://portal.example \
//     node a-page-with-only-the-sdk.mjs      # then "start", "poll", "poll-again"
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { startPageSession, readPageSession } from "../dist/page.js";
import { checkSignInInPage } from "../../login-verify/dist/browser.js";

export function aPageWithOnlyTheSdk({ agentUrl, assetId, origin, expectedSiteAid, consume, fetchFn }) {
  const base = fetchFn ?? fetch;
  const asABrowser = (url, init = {}) => base(url, { ...init, headers: { ...init.headers, Origin: origin } });
  const sessionEndpoint = `${agentUrl.replace(/\/$/, "")}/api/login/session/${encodeURIComponent(assetId)}`;
  let started;
  let handed;
  const check = (signIn) =>
    checkSignInInPage(signIn, { agentUrl, expectedAudience: origin, expectedSiteAid, consume, fetchFn: asABrowser });
  return {
    async start(requestDisclosures = ["display_name"]) {
      started = await startPageSession({ sessionEndpoint, body: { requestDisclosures }, fetchFn: asABrowser });
      return { session_token: started.sessionToken, pointer_url: started.pointerUrl };
    },
    // One look at the sign-in. Signed in only when the Identity Agent handed
    // over an assertion and the page's own check passed.
    async poll() {
      const r = await readPageSession({
        sessionEndpoint,
        sessionToken: started.sessionToken,
        collectorSecret: started.collectorSecret,
        fetchFn: asABrowser,
      });
      if (r.state !== "verified") return { state: r.state === "declined" ? "declined" : "pending", reason: r.reason };
      if (r.identityWithheld || !r.assertion) return { state: "withheld" };
      handed = { assertion: r.assertion, nonce: r.nonce, siteAid: r.siteAid, browserKey: r.browserKey };
      const out = await check(handed);
      return out.valid
        ? { state: "signed-in", pairwise_aid: out.pairwiseAID, claimed_by_agent: r.appSessionToken, disclosures: out.disclosures }
        : { state: "refused", reason: out.reason };
    },
    // The same assertion presented to the page's check again.
    async checkAgain() {
      const out = await check(handed);
      return { valid: out.valid, reason: out.reason };
    },
    get collectorSecret() {
      return started?.collectorSecret;
    },
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const page = aPageWithOnlyTheSdk({
    agentUrl: process.env.IA_URL,
    assetId: process.env.ASSET_ID,
    origin: process.env.ORIGIN,
    expectedSiteAid: process.env.SITE_AID || undefined,
  });
  const commands = { start: () => page.start(), poll: () => page.poll(), "poll-again": () => page.checkAgain() };
  console.log(JSON.stringify({ ready: true }));
  for await (const line of createInterface({ input: process.stdin })) {
    let out;
    try {
      out = await commands[line.trim()]();
    } catch (e) {
      out = { error: String(e.message) };
    }
    console.log(JSON.stringify(out));
  }
}
