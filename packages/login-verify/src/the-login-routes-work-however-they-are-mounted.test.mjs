import * as ed from "@noble/ed25519";
import express from "express";
import {
  IdentityAgentVerifier,
  assertionDigest,
  canonicalAssertionBody,
  generateDevSiteIdentity,
  mountIdentityAgentLoginRoutes,
  nonTransferableAidQb64,
  signCanonical,
} from "../dist/index.js";

// The sign-in routes are mounted into the site's own app, which may or may
// not have a JSON body parser of its own, before or after them. Each way, the
// session route must see the options the site's page posted, and the callback
// must read the assertion from its text, so a repeated key is refused.

let failures = 0;
function check(ok, msg) {
  if (!ok) {
    failures++;
    console.error(`FAIL: ${msg}`);
  }
}

const site = await generateDevSiteIdentity("http://relay.example");
const personSeed = ed.utils.randomPrivateKey();
const personPub = await ed.getPublicKeyAsync(personSeed);
const personAid = nonTransferableAidQb64(personPub);

async function signed(fields) {
  const a = {
    v: "IALOGIN10JSON", t: "login-assertion", i: personAid, relationship_aid_oobi: "o",
    dt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"), disclosures: {}, presented_acdcs: [],
    p_kel: "kel", site_aid: site.aid, ...fields,
  };
  a.d = assertionDigest(a);
  a.sig = await signCanonical(canonicalAssertionBody(a), personSeed);
  return a;
}

const layouts = {
  "no parser of the app's own": (app, mount) => mount(app),
  "a JSON parser mounted before the routes": (app, mount) => {
    app.use(express.json());
    mount(app);
  },
  "a JSON parser mounted after the routes": (app, mount) => {
    mount(app);
    app.use(express.json());
  },
};

for (const [layout, build] of Object.entries(layouts)) {
  const verifier = new IdentityAgentVerifier({ siteIdentity: site, resolveKey: async () => personPub });
  const app = express();
  // Something of the app's own that must still run on the callback.
  let appMiddlewareSawCallback = false;
  build(app, (a) => {
    a.use((req, _res, next) => {
      if (req.path === "/auth/ia/callback") appMiddlewareSawCallback = true;
      next();
    });
    mountIdentityAgentLoginRoutes(a, verifier);
  });
  // A route of the app's own that takes JSON, unaffected by the sign-in routes.
  app.post("/app/echo", (req, res) => res.json({ got: req.body ?? null }));
  const server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  const base = `http://127.0.0.1:${server.address().port}`;

  // The session route carries what the site's page asked for into the
  // challenge the Identity Agent fetches.
  const asked = {
    requestDisclosures: ["email"],
    requestCredentials: [{ schema_said: "EX", required: true }],
    requestScore: { min_score: 50, required: true },
    callbackUrl: `${base}/auth/ia/callback`,
  };
  const started = await fetch(`${base}/auth/ia/session`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(asked),
  });
  check(started.status === 200, `${layout}: the session route answered ${started.status}`);
  const { session_token } = await started.json();
  const challenge = await (await fetch(`${base}/i/${session_token}`)).json();
  check(JSON.stringify(challenge.requested_disclosures) === JSON.stringify(["email"]),
    `${layout}: requested disclosures were ${JSON.stringify(challenge.requested_disclosures)}`);
  check(JSON.stringify(challenge.requested_credentials) === JSON.stringify(asked.requestCredentials),
    `${layout}: requested credentials were ${JSON.stringify(challenge.requested_credentials)}`);
  check(challenge.requested_score?.min_score === 50,
    `${layout}: the requested score was ${JSON.stringify(challenge.requested_score)}`);
  check(challenge.callback_url === asked.callbackUrl,
    `${layout}: the callback was ${challenge.callback_url}`);

  // The callback refuses what the core refuses, from the text.
  const a = await signed({ audience: challenge.audience, nonce: challenge.nonce });
  const text = JSON.stringify(a);
  const post = (body) => fetch(`${base}/auth/ia/callback?session=${session_token}`, {
    method: "POST", headers: { "content-type": "application/json" }, body,
  });
  const doubled = await post(text.replace('"nonce":', '"nonce":"another","nonce":'));
  check(doubled.status === 400, `${layout}: a repeated key was answered ${doubled.status}`);
  const bom = await post(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text)]));
  check(bom.status === 400, `${layout}: a byte order mark was answered ${bom.status}`);
  const genuine = await post(text);
  check(genuine.status === 200, `${layout}: the genuine assertion was answered ${genuine.status} ${await genuine.text()}`);
  check(appMiddlewareSawCallback, `${layout}: the app's own middleware did not run on the callback`);

  // The app's own JSON route is untouched.
  const echo = await fetch(`${base}/app/echo`, {
    method: "POST", headers: { "content-type": "application/json" }, body: '{"x":1}',
  });
  const echoed = await echo.json();
  if (layout === "no parser of the app's own") {
    check(echo.status === 200, `${layout}: the app's own route answered ${echo.status}`);
  } else {
    check(echoed.got?.x === 1, `${layout}: the app's own route read ${JSON.stringify(echoed)}`);
  }
  server.close();
}

if (failures) {
  console.error(`${failures} failure(s)`);
  process.exit(1);
}
console.log("the login routes work however they are mounted");
