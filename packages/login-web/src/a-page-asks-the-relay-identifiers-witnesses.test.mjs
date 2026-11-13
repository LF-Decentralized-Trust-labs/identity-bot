// A utility app's page, given a link that names the witnesses of its relay identifier (ADR-072 Amendment 5),
// asks them for the identifier's key log, presenting the inception, and goes by it: a log that carries on
// from what they vouch for is taken as before, a link older than a rotation they vouch for is refused (and
// stays refused), and witnesses that cannot be reached, or have receipted nothing, change nothing.
import assert from "node:assert";
import { b64u, identity, logMemory, nowSeconds, relayChain, sealing, witnessAnswer, witnessFor } from "./app-test-support.mjs";
import { appFetch, readAppLink } from "../dist/app.js";

const app = identity();
const W = [0, 1, 2].map((i) => witnessFor("page-w" + i));
const chain = relayChain("page-witnessed", 2, { b: W.map((w) => w.aid), bt: "2" }); // an inception and two rotations
const receipts = (w, index) => (i, e) => [w.receipt(e.text, index)];
const answer = (w, index, n) => witnessAnswer(chain, n, receipts(w, index));
const urls = ["https://w0.example/api", "https://w1.example/api"];
const mine = { thumbprint: "t", jwk: {}, privateKey: null };

// the link as it was made when the identifier had `n` events: the owner's Identity Agent's statement at that event
const linkAt = async (n, wit = urls) => {
  const at = { ...chain, events: chain.events.slice(0, n), log: () => chain.log(n), sign: (b) => chain.keys[n - 1].sign(b) };
  const sl = await sealing(at);
  const hash = `#aid=${app.aid}&kel=${app.log()}&rid=${chain.aid}&api=https://tasks.example/&seal=${sl.statement}&min=${sl.min}&iat=${nowSeconds()}` + (wit.length ? `&wit=${wit.join(",")}` : "");
  return { link: readAppLink(hash), sl };
};
// what the witnesses answer: by address, the events each holds
const witnesses = (held) => {
  const asked = [];
  const f = async (url, init) => {
    asked.push({ url: String(url), proof: init?.headers?.["X-Inception-Event"] });
    const base = String(url).replace(/\/witness\/kel\/.*/, "");
    const h = held[base];
    if (h === "down") throw new TypeError("network down");
    if (h === "error") return new Response("no", { status: 500 });
    if (!h) return new Response("not held", { status: 404 });
    return new Response(JSON.stringify(h), { status: 200, headers: { "content-type": "application/json" } });
  };
  return { f, asked };
};
const open = (l, w, logs = logMemory()) => appFetch(l.link, { fetchFn: l.sl.wrap(async () => new Response("{}")), browserKey: async () => mine, logs, witnessFetch: w.f });
const refuses = (p, re, what) => assert.rejects(p, (e) => re.test(e.message), what);

// witnesses that vouch for what the link carries: taken, and each was asked, with the inception as proof
{
  const l = await linkAt(3);
  const w = witnesses({ "https://w0.example/api": answer(W[0], 0, 3), "https://w1.example/api": answer(W[1], 1, 3) });
  await open(l, w);
  assert.deepEqual(w.asked.map((a) => a.url).sort(), urls.map((u) => `${u}/witness/kel/${chain.aid}`));
  assert.equal(Buffer.from(w.asked[0].proof, "base64url").toString(), chain.events[0].text, "the inception, as published, is what is presented");
}
// witnesses not yet told of the last rotation (a removal does not wait for them): the link's log is taken
{
  const w = witnesses({ "https://w0.example/api": answer(W[0], 0, 2), "https://w1.example/api": answer(W[1], 1, 2) });
  await open(await linkAt(3), w);
}
// witnesses that vouch for a rotation the link's log does not have: the key the link vouched for has been rotated away
{
  const logs = logMemory();
  const w = witnesses({ "https://w0.example/api": answer(W[0], 0, 3), "https://w1.example/api": answer(W[1], 1, 3) });
  const old = await linkAt(2);
  await refuses(open(old, w, logs), /moved on since this link was made/, "a link made before a rotation the witnesses vouch for");
  assert.equal(logs.get(chain.aid), chain.log(3), "the witnessed log is kept");
  // and it stays refused with no witness to ask: the page remembers
  await refuses(open(await linkAt(2, []), witnesses({}), logs), /behind or apart/, "the same link, later, with the witnesses out of reach");
}
// witnesses that cannot be reached, answer an error, hold nothing, or have receipted too little: nothing changes
for (const [what, held] of [
  ["down", { "https://w0.example/api": "down", "https://w1.example/api": "down" }],
  ["erroring", { "https://w0.example/api": "error", "https://w1.example/api": "error" }],
  ["not holding the log", {}],
  ["with one receipt where two are needed", { "https://w0.example/api": answer(W[0], 0, 3) }],
]) await open(await linkAt(2), witnesses(held)), what;
// a link naming no witnesses asks none
{
  const w = witnesses({});
  await open(await linkAt(3, []), w);
  assert.equal(w.asked.length, 0);
}
console.log("a page asks the relay identifier's witnesses, and is refused a link older than a rotation they vouch for");
