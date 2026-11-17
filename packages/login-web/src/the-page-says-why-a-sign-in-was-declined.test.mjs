// A sign-in the Identity Agent closed with a reason is shown with that reason in
// words and what the person can do about it, not as a bare "declined", which
// reads as though they pressed No on their phone.
import assert from "node:assert";
import { readPageSession } from "../dist/pageSession.js";
import { pollProblem, refusalInWords, refusalNextStep, refusalProblem, signInProblem } from "../dist/signInProblem.js";

const declined = await readPageSession({
  sessionEndpoint: "https://ia.example/api/login/session/the-site",
  sessionToken: "tok",
  collectorSecret: "s3cret",
  fetchFn: async () => ({ ok: true, json: async () => ({ state: "declined", reason: "this key already speaks for another person" }) }),
});
assert.equal(declined.state, "declined");
assert.equal(declined.reason, "this key already speaks for another person");

// Each reason the core closes a sign-in with gets its own words and its own way on.
const said = {
  "the asset this sign-in was for is gone": /no longer set up on its owner's Identity Agent.*Tell the utility app's owner/,
  "the installed app's key was not proved for this sign-in": /could not confirm the key of this installed copy.*try again/,
  "this key already speaks for another person": /already signs in another person.*another browser/,
  "the sign-in could not be recorded": /could not record it.*try again/,
};
for (const [reason, words] of Object.entries(said)) {
  const s = signInProblem("declined", reason);
  assert.match(s, words, reason);
  assert.doesNotMatch(s, /Either you declined it on your phone/, reason + ": shown as a bare decline");
  assert.ok(!s.includes(reason), reason + ": the code's own words are shown to a person");
}
// A reason not known here is shown as it was said, never swallowed.
assert.match(signInProblem("declined", "the roster is closed today"), /not accepted: the roster is closed today\. Press the button to try again/);
// With no reason the older wording stands.
assert.match(signInProblem("declined"), /Either you declined it on your phone/);
assert.match(signInProblem("declined", "  "), /Either you declined it on your phone/);
// A refusal that leaves the sign-in open (its last_refusal) is said in words too:
// every reason the core keeps there, with whether approving again can help or
// only the utility app's owner can.
const refusals = [
  ["an answer could not be verified, and was not accepted", /could not be confirmed as coming from your Identity Agent/, "again"],
  ["asset store unavailable", /could not read this utility app's settings/, "again"],
  ["the website's settings could not be read", /could not read this utility app's settings/, "again"],
  ["asset not found", /not set up on its owner's Identity Agent/, "owner"],
  ["not a member of this asset", /not on this utility app's list of people who may sign in/, "owner"],
  ["no membership resolver for source: employees", /owner's Identity Agent cannot check/, "owner"],
  ["the required credential was not presented", /asks for a credential your Identity Agent did not present/, "owner"],
  ["the credential could not be checked", /presented could not be checked/, "again"],
  ["the credential is not accepted here", /not one this utility app accepts/, "owner"],
  ["minimum score gate is not available yet", /minimum score, which cannot be checked yet/, "owner"],
  ["badge gate is not available yet", /badge, which cannot be checked yet/, "owner"],
  ["assurance level gate is not available yet", /assurance level, which cannot be checked yet/, "owner"],
  ["the owner's front-end setting could not be read", /which ways of signing in to this utility app are switched on/, "again"],
  ["this sign-in does not say which front end it is for, 'browser' or 'installed_app'", /did not say whether it came from a browser or an installed copy/, "owner"],
  ["this utility app does not offer a browser front end", /cannot be signed in to from a browser$/, "owner"],
  ["this utility app does not offer a installed-app front end", /cannot be signed in to from an installed copy of it$/, "owner"],
  ["the owner of this utility app has switched off its browser front end", /switched off signing in from a browser$/, "owner"],
  ["the owner of this utility app has switched off its installed-app front end", /switched off signing in from an installed copy of it$/, "owner"],
];
for (const [reason, words, next] of refusals) {
  assert.match(refusalInWords(reason), words, reason);
  assert.equal(refusalNextStep(reason), next, reason);
  const line = refusalProblem(reason);
  assert.ok(line.startsWith("That answer was refused: "), reason);
  if (next === "owner") {
    assert.match(line, /owner/, reason + ": does not say it is for the owner");
    assert.doesNotMatch(line, /still open, so you can approve it again/, reason);
  } else {
    assert.match(line, /still open, so you can approve it again/, reason);
  }
}
// Where trying again as before cannot help, the line says so, and the ones that
// need something else name what to do, not only who to tell.
for (const reason of ["asset not found", "not a member of this asset", "the credential is not accepted here", "badge gate is not available yet", "the owner of this utility app has switched off its browser front end"]) {
  assert.match(refusalProblem(reason), /will not help/, reason + ": tells the person to retry something a retry cannot fix");
}
assert.match(refusalProblem("the required credential was not presented"), /from an Identity Agent that holds that credential/);
assert.match(refusalProblem("not a member of this asset"), /Ask the utility app's owner to add you/);
assert.match(refusalProblem("the owner of this utility app has switched off its browser front end"), /Sign in another way the owner allows/);
// A source name cut short by the core's length limit is still known.
assert.equal(refusalNextStep("no membership resolver for source: a-very-long-na"), "owner");
// A reason not known here is shown as said, and a retry is not ruled out.
assert.equal(refusalInWords("  not today  "), "not today");
assert.match(refusalProblem("not today"), /^That answer was refused: not today\. The sign-in is still open/);
// A sign-in closed with a reason only the owner can fix does not say "try again".
assert.match(signInProblem("declined", "not a member of this asset"), /will not help until the utility app's owner changes this/);
assert.match(signInProblem("declined", "the credential could not be checked"), /Press the button to try again/);

// The page's poll: a decline is said with its reason, never with a stale error,
// and an error with the error, never with a reason.
assert.match(pollProblem({ state: "declined", reason: "this key already speaks for another person", error: "HTTP 503" }), /another browser/);
assert.match(pollProblem({ state: "declined", error: "HTTP 503" }), /Either you declined it on your phone/);
assert.match(pollProblem({ state: "error", reason: "this key already speaks for another person", error: "HTTP 503" }), /cannot be reached right now/);
assert.match(pollProblem({ state: "expired", reason: "x" }), /ran out of time/);
console.log("ok");
