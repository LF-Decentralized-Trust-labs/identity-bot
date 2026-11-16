// A utility app's page lists where a person is signed in in plain words, signs another
// one out, sets the limit, and says so in a sentence when its own session is gone.
import assert from "node:assert";
import { SessionEnded } from "../dist/app.js";
import { ago, describe, limitLine, mountSessions } from "../dist/sessionsPanel.js";

assert.equal(ago("2030-01-01T00:00:00Z", Date.parse("2030-01-01T00:00:30Z")), "just now");
assert.equal(ago("2030-01-01T00:00:00Z", Date.parse("2030-01-01T00:05:00Z")), "5 minutes ago");
assert.equal(ago("2030-01-01T00:00:00Z", Date.parse("2030-01-01T01:00:00Z")), "1 hour ago");
assert.equal(ago("2030-01-01T00:00:00Z", Date.parse("2030-01-04T00:00:00Z")), "3 days ago");
assert.equal(ago("not a time", 0), "a while ago");
assert.match(limitLine({ max: 0, app_max: 0, own_max: 0 }), /any number/);
assert.match(limitLine({ max: 2, app_max: 2, own_max: 0 }), /at most 2 browsers.*this app's own limit/);
assert.doesNotMatch(limitLine({ max: 2, app_max: 5, own_max: 2 }), /this app's own/);

// A page's elements, as far as the panel uses them.
function el(tag) {
  const e = { tag, children: [], textContent: "", attrs: {}, setAttribute(k, v) { this.attrs[k] = v; }, append(...c) { this.children.push(...c); }, ownerDocument: null };
  Object.defineProperty(e, "textContent", { get() { return this._t ?? ""; }, set(v) { this._t = v; if (v === "") this.children = []; } });
  return e;
}
const doc = { createElement: el };
const root = el("div"); root.ownerDocument = doc;
const texts = (n) => [n._t ?? "", ...n.children.flatMap(texts)];
const find = (n, tag) => [n.tag === tag ? [n] : [], ...n.children.map((c) => find(c, tag))].flat(2);

const now = Date.parse("2030-01-01T01:00:00Z");
let state = { sessions: [
  { key: "KB", started: "2030-01-01T00:00:00Z", last_used: "2030-01-01T00:55:00Z", current: false },
  { key: "KA", started: "2030-01-01T00:30:00Z", last_used: "2030-01-01T01:00:00Z", current: true },
], max: 0, app_max: 0, own_max: 0 };
const calls = [];
const session = { call: async (method, path, body = "") => {
  calls.push([method, path, body]);
  if (path === "/session/sessions") return { status: 200, bytes: new Uint8Array(), json: () => state };
  if (path === "/session/sessions/end") { state = { ...state, sessions: state.sessions.filter((s) => s.key !== JSON.parse(body).key) }; return { status: 200, json: () => ({}) }; }
  if (path === "/session/sessions/limit") { state = { ...state, own_max: JSON.parse(body).max, max: JSON.parse(body).max }; return { status: 200, json: () => ({}) }; }
  throw new Error("unexpected " + path);
} };
const problems = [], ended = [];
await mountSessions(root, session, { onEnded: (e) => ended.push(e), onProblem: (t) => problems.push(t) }, () => now);

let lines = find(root, "li").map((l) => texts(l).join(""));
assert.deepEqual(lines.map((l) => l.replace(/Sign this one out/, "").trim()), [
  "Another browser: signed in 1 hour ago, last used 5 minutes ago",
  "This device: signed in 30 minutes ago, last used just now",
]);
assert.equal(find(root, "button").length, 1, "this device has no sign-out button: that is the page's own sign out");

// Sign the other one out: the list is read again and it is gone.
await find(root, "button")[0].onclick();
assert.deepEqual(calls.at(-2), ["POST", "/session/sessions/end", JSON.stringify({ key: "KB" })]);
assert.equal(find(root, "li").length, 1);

// Set a limit.
const select = find(root, "select")[0];
select.value = "2";
await select.onchange();
assert.deepEqual(calls.at(-2), ["POST", "/session/sessions/limit", JSON.stringify({ max: 2 })]);
assert.match(texts(root).join(" "), /at most 2 browsers/);

// An ended own session is handed back to the page, not shown as a failure.
const gone = { call: async () => { throw new SessionEnded(); } };
const root2 = el("div"); root2.ownerDocument = doc;
await mountSessions(root2, gone, { onEnded: (e) => ended.push(e), onProblem: (t) => problems.push(t) }, () => now);
assert.equal(ended.length, 1);
assert.deepEqual(problems, []);

// An app that will not answer is told in words.
const bad = { call: async () => ({ status: 500, json: () => ({}) }) };
await mountSessions(root2, bad, { onEnded() {}, onProblem: (t) => problems.push(t) }, () => now);
assert.match(problems[0], /would not list where you are signed in/);
console.log("ok");
