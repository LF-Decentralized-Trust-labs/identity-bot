import assert from "node:assert/strict";
import { buildLoginQrUrl, isRpHostedOobi } from "../dist/qr-url.js";

const SESSION = "Joy6X61xwxdQhhQ-8XvK1L";

// The QR is a bare Ask pointer on the RP origin (== audience),
// `/i/{token}` — one-char namespace + the session token. No oobi/AID, no action,
// no rp, no session= query. Everything else is in the signed Ask fetched after scan.
assert.equal(
  buildLoginQrUrl("https://asgcc.replit.app", SESSION),
  `https://asgcc.replit.app/i/${SESSION}`,
);

// Trailing slash on the origin is normalized away.
assert.equal(
  buildLoginQrUrl("https://asgcc.replit.app/", SESSION),
  `https://asgcc.replit.app/i/${SESSION}`,
);

// Custom namespace is honored (and slash-normalized).
assert.equal(
  buildLoginQrUrl("https://asgcc.replit.app", SESSION, "r"),
  `https://asgcc.replit.app/r/${SESSION}`,
);

// isRpHostedOobi remains a valid helper for the legacy OOBI copy-link form.
assert.equal(isRpHostedOobi("https://asgcc.replit.app/auth/ia/site/oobi/EAID"), true);
assert.equal(isRpHostedOobi("https://relay.grapeid.org/oobi/EAID"), false);

console.log("qr-url.test.mjs: ok");
