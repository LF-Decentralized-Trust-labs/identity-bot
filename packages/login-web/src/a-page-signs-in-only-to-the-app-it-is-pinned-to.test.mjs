// A hosted utility app's page signs in only to the app its own configuration pins: the app's
// identifier and key log, the relay identifier, the back end's address, the relay identifier's latest
// key log event and its witnesses. A link naming another app, relay identifier or back end is refused,
// and so is one that would check the relay identifier's key log less than the pin does; a page with no
// pin signs nobody in; and a page opened with no link builds one from the pin and a live statement.
import assert from "node:assert";
import { identity, logMemory, minimum, nowSeconds, relayChain, sealing } from "./app-test-support.mjs";
import {
  AppUnreachable, checkAppKeyLog, checkedSealKey, checkSealKey, loadPinnedApp, pinAppLink, pinnedAppLink, readAppLink, readPinnedApp, readPinnedAppLink,
} from "../dist/app.js";
import { probesSameDevice } from "../dist/SignInButton.js";

const app = identity();
const relay = relayChain("pinned", 2);
const sl = await sealing(relay);
const W1 = "https://w1.example", W2 = "https://w2.example";
const pin = { aid: app.aid, kel: app.log(), rid: relay.aid, api: "https://tasks.example", min: minimum(relay, 2), wit: [W1] };
const config = (over = {}) => ({ app: { aid: pin.aid, kel: pin.kel, rid: pin.rid, api: pin.api, min: pin.min, wit: W1, ...over } });
const hash = (over = {}) => {
  const v = { aid: app.aid, kel: app.log(), rid: relay.aid, api: "https://tasks.example/", seal: sl.statement, min: sl.min, wit: W1, iat: String(nowSeconds()), ...over };
  return "#" + new URLSearchParams(v).toString();
};

// a link that names the pinned app is taken, with the pinned minimum carried as its floor
assert.deepEqual(readPinnedAppLink(hash(), pin), { ...readAppLink(hash()), floor: pin.min });
assert.equal(readPinnedAppLink(hash({ wit: `${W1},${W2}` }), pin).wit.length, 2, "a link may name more witnesses than the pin");

// a link naming another app, relay identifier or back end is refused, saying which
const other = identity();
const otherRelay = relayChain("other");
assert.throws(() => readPinnedAppLink(hash({ aid: other.aid, kel: other.log() }), pin), /names a different utility app than the one this page belongs to/);
assert.throws(() => readPinnedAppLink(hash({ rid: otherRelay.aid }), pin), /names a different relay identifier than the one this page belongs to/);
assert.throws(() => readPinnedAppLink(hash({ api: "https://evil.example" }), pin), /names a different back end than the one this page belongs to/);
assert.throws(() => readPinnedAppLink(hash({ api: "https://tasks.example/elsewhere" }), pin), /a different back end/);
assert.throws(() => readPinnedAppLink(hash({ api: "http://127.0.0.1:5050" }), pin), /a different back end/);

// the back end is compared byte for byte, never case-folded: one spelling is taken, and a pin must be written in it
assert.throws(() => readPinnedAppLink(hash({ api: "https://Tasks.example" }), pin), /a different back end/, "a host in another case");
assert.throws(() => readPinnedAppLink(hash({ api: "HTTPS://tasks.example" }), pin), /no back end|a different back end/, "a scheme in another case");
assert.equal(readPinnedAppLink(hash({ api: "https://tasks.example/A" }), { ...pin, api: "https://tasks.example/A" }).api, "https://tasks.example/A");
assert.throws(() => readPinnedAppLink(hash({ api: "https://tasks.example/a" }), { ...pin, api: "https://tasks.example/A" }), /a different back end/, "a path in another case");
assert.throws(() => readPinnedApp(config({ api: "https://Tasks.example" })), /no back end, written in lower case/);
assert.throws(() => readPinnedApp(config({ api: "https://tasks.example/" })), /no trailing slash/);

// a link cannot check the relay identifier's key log less than the pin does
assert.throws(() => readPinnedAppLink(hash({ wit: W2 }), pin), /leaves out a witness/, "a pinned witness left out");
assert.throws(() => readPinnedAppLink(hash({ wit: "" }), pin), /leaves out a witness/, "no witnesses at all");
assert.throws(() => readPinnedAppLink(hash({ min: minimum(relay, 1) }), pin), /an earlier key log/, "a minimum below the pin's");
assert.throws(() => readPinnedAppLink(hash({ min: `1.${otherRelay.events[0].said}` }), pin), /an earlier key log/, "the pin's number with another event");
assert.equal(readPinnedAppLink(hash({ min: minimum(relay, 3) }), pin).min, minimum(relay, 3), "a later minimum is taken");
// and every sealing key statement is held to the pinned minimum as well as the link's
{
  await assert.rejects(checkSealKey(relay.aid, sl.statement, null, minimum(relay, 1), `2.${otherRelay.events[0].said}`), /does not reach the event this page is pinned to/);
  await checkSealKey(relay.aid, sl.statement, null, minimum(relay, 1), pin.min);
}

// the key log is the link's (it may be newer than any pin) but only one the pinned identifier derives is taken
const kept = readPinnedAppLink(hash(), pin);
assert.deepEqual(await checkAppKeyLog(kept.aid, kept.kel), app.key);
const swapped = readPinnedAppLink(hash({ kel: other.log() }), pin);
await assert.rejects(checkAppKeyLog(swapped.aid, swapped.kel), /not the utility app's identifier/);

// the pin is read again wherever it is handed in: by pinAppLink ...
for (const bad of [{ ...pin, api: "http://evil.example" }, { ...pin, min: "x" }, { ...pin, kel: "" }, { ...pin, aid: "{{APP_AID}}" }]) {
  assert.throws(() => pinAppLink(readAppLink(hash()), bad), /not set up to sign anybody in/, JSON.stringify(bad));
}
assert.throws(() => pinAppLink(readAppLink(hash()), undefined), /pinned to no utility app/);
// ... and by readPinnedAppLink, before the link is read at all
for (const bad of [{ ...pin, rid: "" }, { ...pin, wit: ["http://evil.example"] }, { aid: app.aid }]) {
  assert.throws(() => readPinnedAppLink("#not-a-link", bad), /not set up to sign anybody in/, JSON.stringify(bad));
}
for (const none of [undefined, null]) assert.throws(() => readPinnedAppLink(hash(), none), /not set up to sign anybody in: it is pinned to no utility app/);

// no pin, or half a pin, no sign-in
for (const [c, why] of [
  [undefined, /names no utility app$/],
  [{}, /names no utility app$/],
  [{ link: hash() }, /names no utility app$/],
  [config({ aid: "{{APP_AID}}" }), /no utility app identifier/],
  [config({ kel: undefined }), /no key log/],
  [config({ rid: "" }), /no relay identifier/],
  [config({ api: "http://evil.example" }), /no back end/],
  [config({ api: undefined }), /no back end/],
  [config({ min: undefined }), /no latest key log event/],
  [config({ wit: undefined }), /witnesses are/],
  [config({ wit: "ftp://w.example" }), /witness address/],
]) assert.throws(() => readPinnedApp(c), why, JSON.stringify(c));
assert.deepEqual(readPinnedApp({ ...config(), console_origin: "https://c.example" }), pin);
assert.deepEqual(readPinnedApp(config({ wit: "none" })).wit, []);

// the page's own config.json: read same-origin, never cached, no credentials; missing or pin-less is no sign-in
{
  const asked = [];
  const serve = (status, body) => async (url, init) => { asked.push([url, init]); return new Response(body, { status }); };
  assert.deepEqual(await loadPinnedApp(serve(200, JSON.stringify(config()))), pin);
  assert.deepEqual(asked[0], ["config.json", { cache: "no-store", credentials: "omit" }]);
  await assert.rejects(loadPinnedApp(serve(404, "")), /not set up to sign anybody in: it has no configuration beside it \(HTTP 404\)/);
  await assert.rejects(loadPinnedApp(serve(200, "<html>")), /configuration is not JSON/);
  await assert.rejects(loadPinnedApp(serve(200, JSON.stringify({ link: hash() }))), /names no utility app/);
  await assert.rejects(loadPinnedApp(async () => { throw new TypeError("offline"); }), /could not be read/);
}

// a page opened with no link builds one from the pin and the statement in force, with nothing that lapses
{
  const asked = [];
  const backEnd = async (url, init) => { asked.push([String(url), init.method]); return new Response(sl.statement, { status: 200 }); };
  const unpinned = { ...pin, wit: [] };
  const l = await pinnedAppLink(unpinned, backEnd);
  assert.deepEqual(asked, [["https://tasks.example/sealing-key", "GET"]]);
  assert.deepEqual(l, { aid: app.aid, kel: app.log(), rid: relay.aid, api: "https://tasks.example", seal: sl.statement, min: pin.min, wit: [], floor: pin.min });
  assert.equal("iat" in l, false, "nothing in it has a lifetime");
  await checkedSealKey(l, logMemory(), backEnd);
  await assert.rejects(pinnedAppLink(unpinned, async () => new Response("", { status: 503 })), AppUnreachable);
  await assert.rejects(pinnedAppLink(unpinned, async () => { throw new TypeError("offline"); }), AppUnreachable);
  await assert.rejects(pinnedAppLink(null, backEnd), /pinned to no utility app/);
  // a statement from before the pinned event is refused when it is checked, before any call
  const old = await pinnedAppLink({ ...unpinned, min: `3.${otherRelay.events[0].said}` }, backEnd);
  await assert.rejects(checkedSealKey(old, logMemory(), backEnd), /does not reach/);
}

// a website's button looks for an Identity Agent on this device; a utility app's page never does unless told to
assert.equal(probesSameDevice(undefined), true, "a website, by default");
assert.equal(probesSameDevice("browser"), false, "a utility app's page, by default");
assert.equal(probesSameDevice(undefined, false), false, "a website told not to");
assert.equal(probesSameDevice("browser", true), true, "a page told to");
console.log("a page signs in only to the utility app it is pinned to, checks its key log at least as the pin does, and with no pin signs nobody in");
