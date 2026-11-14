// A hosted utility app's page signs in only to the app its own configuration pins: the app's
// identifier, the relay identifier and the back end's address. A link naming any other is refused,
// so a crafted link opened on the real page cannot run the sign-in against another back end; a page
// with no pin signs nobody in; and a link's key log is taken only when it derives the pinned identifier.
import assert from "node:assert";
import { identity, nowSeconds, relayChain, sealing } from "./app-test-support.mjs";
import { checkAppKeyLog, loadPinnedApp, pinAppLink, readAppLink, readPinnedApp, readPinnedAppLink } from "../dist/app.js";

const app = identity();
const relay = relayChain("relay");
const sl = await sealing(relay);
const pin = { aid: app.aid, rid: relay.aid, api: "https://tasks.example" };
const hash = (over = {}) => {
  const v = { aid: app.aid, kel: app.log(), rid: relay.aid, api: "https://tasks.example/", seal: sl.statement, min: sl.min, iat: String(nowSeconds()), ...over };
  return "#" + new URLSearchParams(v).toString();
};

// a link that names the pinned app is taken, a trailing slash on either address no matter
assert.deepEqual(readPinnedAppLink(hash(), pin), readAppLink(hash()));
assert.equal(readPinnedAppLink(hash({ api: "https://tasks.example" }), { ...pin, api: "https://tasks.example/" }).api, "https://tasks.example");

// a link naming another app, relay identifier or back end is refused, saying which
const other = identity();
const otherRelay = relayChain("other");
assert.throws(() => readPinnedAppLink(hash({ aid: other.aid, kel: other.log() }), pin), /a different utility app than the one this page belongs to/);
assert.throws(() => readPinnedAppLink(hash({ rid: otherRelay.aid }), pin), /a different relay identifier than the one this page belongs to/);
assert.throws(() => readPinnedAppLink(hash({ api: "https://evil.example" }), pin), /a different back end than the one this page belongs to/);
assert.throws(() => readPinnedAppLink(hash({ api: "https://tasks.example/elsewhere" }), pin), /a different back end/);
assert.throws(() => readPinnedAppLink(hash({ api: "http://127.0.0.1:5050" }), pin), /a different back end/);
assert.throws(() => pinAppLink(readAppLink(hash()), { ...pin, aid: other.aid }), /a different utility app/);

// the key log is the link's (it may be newer than any pin) but only one the pinned identifier derives is taken
const kept = readPinnedAppLink(hash(), pin);
assert.deepEqual(await checkAppKeyLog(kept.aid, kept.kel), app.key);
const swapped = readPinnedAppLink(hash({ kel: other.log() }), pin);
await assert.rejects(checkAppKeyLog(swapped.aid, swapped.kel), /not the utility app's identifier/);

// no pin, no sign-in
for (const none of [undefined, null]) assert.throws(() => readPinnedAppLink(hash(), none), /not set up to sign anybody in: it is pinned to no utility app/);
for (const [config, why] of [
  [undefined, /names no utility app$/],
  [{}, /names no utility app$/],
  [{ link: hash() }, /names no utility app$/],
  [{ app: { aid: "{{APP_AID}}", rid: relay.aid, api: "https://tasks.example" } }, /no utility app identifier/],
  [{ app: { aid: app.aid, rid: "", api: "https://tasks.example" } }, /no relay identifier/],
  [{ app: { aid: app.aid, rid: relay.aid, api: "http://evil.example" } }, /no back end/],
  [{ app: { aid: app.aid, rid: relay.aid } }, /no back end/],
]) assert.throws(() => readPinnedApp(config), why, JSON.stringify(config));
assert.throws(() => readPinnedAppLink(hash(), { aid: app.aid, rid: relay.aid, api: "" }), /not set up to sign anybody in/);
assert.deepEqual(readPinnedApp({ app: { ...pin, api: "https://tasks.example/" }, console_origin: "https://c.example" }), pin);

// the page's own config.json: read same-origin, never cached, no credentials; missing or pin-less is no sign-in
{
  const asked = [];
  const serve = (status, body) => async (url, init) => { asked.push([url, init]); return new Response(body, { status }); };
  assert.deepEqual(await loadPinnedApp(serve(200, JSON.stringify({ app: pin }))), pin);
  assert.deepEqual(asked[0], ["config.json", { cache: "no-store", credentials: "omit" }]);
  await assert.rejects(loadPinnedApp(serve(404, "")), /not set up to sign anybody in: it has no configuration beside it \(HTTP 404\)/);
  await assert.rejects(loadPinnedApp(serve(200, "<html>")), /configuration is not JSON/);
  await assert.rejects(loadPinnedApp(serve(200, JSON.stringify({ link: hash() }))), /names no utility app/);
  await assert.rejects(loadPinnedApp(async () => { throw new TypeError("offline"); }), /could not be read/);
}
console.log("a page signs in only to the utility app it is pinned to, and with no pin signs nobody in");
