import * as ed from "@noble/ed25519";
import express from "express";
import {
  IdentityAgentVerifier,
  assertionDigest,
  canonicalAssertionBody,
  generateDevSiteIdentity,
  identityAgentCallbackBody,
  keepLoginRawBody,
  mountIdentityAgentLoginRoutes,
  nonTransferableAidQb64,
  signCanonical,
} from "../dist/index.js";

// The sign-in routes are mounted into the site's own app: at the top, in a
// Router or in a sub-app, with or without a JSON body parser of the app's own.
// Every way, the session route must see the options the site's page posted.
// The callback must read the assertion from its text, so a repeated key is
// refused: an app with no parser needs nothing more, and one with a parser
// mounts identityAgentCallbackBody() first or gives the parser keepLoginRawBody.
// Without either, the callback is refused by name rather than checked from
// what the parser left.

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

// Each layout returns the path the routes sit under, which is also given
// up front so a parser layout can name the callback's full path.
const prefixes = { "at the top": "", "in a Router": "", "in a Router at /login": "/login", "in a sub-app at /login": "/login" };
const mounts = {
  "at the top": (app, v) => { mountIdentityAgentLoginRoutes(app, v); return ""; },
  "in a Router": (app, v) => { const r = express.Router(); mountIdentityAgentLoginRoutes(r, v); app.use(r); return ""; },
  "in a Router at /login": (app, v) => { const r = express.Router(); mountIdentityAgentLoginRoutes(r, v); app.use("/login", r); return "/login"; },
  "in a sub-app at /login": (app, v) => { const s = express(); mountIdentityAgentLoginRoutes(s, v); app.use("/login", s); return "/login"; },
};
const parsers = {
  "no parser of the app's own": { kept: true, before: () => {} },
  "a JSON parser after the routes": { kept: true, after: (app) => app.use(express.json()) },
  "a JSON parser first": { kept: false, before: (app) => app.use(express.json()) },
  "a text parser for everything first": { kept: false, before: (app) => app.use(express.text({ type: "*/*" })) },
  "identityAgentCallbackBody() then a JSON parser": {
    kept: true, before: (app, prefix) => { app.use(identityAgentCallbackBody({ path: `${prefix}/auth/ia/callback` })); app.use(express.json()); },
  },
  "a JSON parser with keepLoginRawBody": { kept: true, before: (app) => app.use(express.json({ verify: keepLoginRawBody })) },
};

for (const [where, mount] of Object.entries(mounts)) {
  for (const [parser, { kept, before, after }] of Object.entries(parsers)) {
    const layout = `${where}, ${parser}`;
    const verifier = new IdentityAgentVerifier({ siteIdentity: site, resolveKey: async () => personPub });
    const app = express();
    // Something of the app's own that must still run on the callback.
    let appMiddlewareSawCallback = false;
    app.use((req, _res, next) => {
      if (req.path.endsWith("/auth/ia/callback")) appMiddlewareSawCallback = true;
      next();
    });
    before?.(app, prefixes[where]);
    const prefix = mount(app, verifier);
    after?.(app);
    // A route of the app's own, unaffected by the sign-in routes.
    app.post("/app/echo", (req, res) => res.json({ got: req.body ?? null }));
    const server = app.listen(0, "127.0.0.1");
    await new Promise((r) => server.once("listening", r));
    const root = `http://127.0.0.1:${server.address().port}`;
    const base = root + prefix;

    // The session route carries what the site's page asked for into the
    // challenge the Identity Agent fetches, and names the callback where it is.
    const asked = {
      requestDisclosures: ["email"],
      requestCredentials: [{ schema_said: "EX", required: true }],
      requestScore: { min_score: 50, required: true },
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
    check(challenge.callback_url === `${base}/auth/ia/callback`, `${layout}: the callback was ${challenge.callback_url}`);

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
    const said = await genuine.text();
    if (kept) {
      check(genuine.status === 200, `${layout}: the genuine assertion was answered ${genuine.status} ${said}`);
    } else {
      check(genuine.status === 400 && said.includes("identityAgentCallbackBody()") && said.includes("keepLoginRawBody"),
        `${layout}: with its text gone the callback was answered ${genuine.status} ${said}`);
    }
    check(appMiddlewareSawCallback, `${layout}: the app's own middleware did not run on the callback`);

    // The app's own route reads its body as it would without the sign-in routes.
    const echo = await fetch(`${root}/app/echo`, {
      method: "POST", headers: { "content-type": "application/json" }, body: '{"x":1}',
    });
    const { got } = await echo.json();
    const want = parser === "no parser of the app's own" ? null
      : parser === "a text parser for everything first" ? '{"x":1}' : { x: 1 };
    check(JSON.stringify(got) === JSON.stringify(want), `${layout}: the app's own route read ${JSON.stringify(got)}`);
    server.close();
  }
}

// identityAgentCallbackBody() reads the callback's body and nothing else: not
// an app route of its own whose path merely ends the same way. It matches the
// callback as Express routes it, so a path in another case or with a trailing
// slash, which Express sends to the callback, is still read as sent.
{
  const verifier = new IdentityAgentVerifier({ siteIdentity: site, resolveKey: async () => personPub });
  const app = express();
  app.use(identityAgentCallbackBody());
  app.use(express.json());
  mountIdentityAgentLoginRoutes(app, verifier);
  app.post("/webhooks/auth/ia/callback", (req, res) => res.json({ got: req.body ?? null }));
  const server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  const root = `http://127.0.0.1:${server.address().port}`;

  const own = await fetch(`${root}/webhooks/auth/ia/callback`, {
    method: "POST", headers: { "content-type": "application/json" }, body: '{"x":1}',
  });
  const { got } = await own.json();
  check(got?.x === 1, `the app's own /webhooks/auth/ia/callback read ${JSON.stringify(got)}`);

  for (const path of ["/Auth/IA/Callback", "/auth/ia/callback/"]) {
    const { session_token, bundle } = await verifier.createChallenge({
      audience: "https://app.example", requestedDisclosures: [], callbackUrl: `${root}${path}`,
    });
    const text = JSON.stringify(await signed({ audience: bundle.audience, nonce: bundle.nonce }));
    const post = (body) => fetch(`${root}${path}?session=${session_token}`, {
      method: "POST", headers: { "content-type": "application/json" }, body,
    });
    const doubled = await post(text.replace('"nonce":', '"nonce":"another","nonce":'));
    check(doubled.status === 400, `${path}: a repeated key was answered ${doubled.status}`);
    const genuine = await post(text);
    check(genuine.status === 200, `${path}: the genuine assertion was answered ${genuine.status} ${await genuine.text()}`);
  }
  server.close();
}

// A body larger than a sign-in sends is answered 413, not dropped, whether
// the route reads it or identityAgentCallbackBody() does.
for (const [layout, build] of Object.entries({
  "no parser": () => {},
  "identityAgentCallbackBody() first": (app) => { app.use(identityAgentCallbackBody()); app.use(express.json()); },
})) {
  const verifier = new IdentityAgentVerifier({ siteIdentity: site, resolveKey: async () => personPub });
  const app = express();
  build(app);
  mountIdentityAgentLoginRoutes(app, verifier);
  const server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  const root = `http://127.0.0.1:${server.address().port}`;
  const huge = '{"v":"' + "x".repeat((1 << 20) + 1024) + '"}';
  for (const path of ["/auth/ia/callback?session=s", "/auth/ia/session"]) {
    if (path === "/auth/ia/session" && layout !== "no parser") continue;
    let status;
    try {
      status = (await fetch(`${root}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: huge })).status;
    } catch (e) {
      status = `a dropped connection (${e.cause?.code ?? e.message})`;
    }
    check(status === 413, `${layout}: an oversize body at ${path.split("?")[0]} was answered ${status}`);
  }
  server.close();
}

if (failures) {
  console.error(`${failures} failure(s)`);
  process.exit(1);
}
console.log("the login routes work however they are mounted");
