// While a sign-in is open after a refusal, the page reads why, so the person
// can fix it and try again.
import assert from "node:assert";
import { readPageSession } from "../dist/pageSession.js";

const read = (body) =>
  readPageSession({
    sessionEndpoint: "https://ia.example/api/login/session/the-site",
    sessionToken: "tok",
    collectorSecret: "s3cret",
    fetchFn: async () => ({ ok: true, json: async () => body }),
  });

const refused = await read({ state: "connecting", last_refusal: "not a member of this asset" });
assert.equal(refused.state, "connecting");
assert.equal(refused.lastRefusal, "not a member of this asset");

const none = await read({ state: "connecting" });
assert.equal(none.lastRefusal, undefined);
console.log("ok");
