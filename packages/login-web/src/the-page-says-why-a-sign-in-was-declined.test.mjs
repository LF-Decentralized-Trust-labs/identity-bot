// A sign-in the Identity Agent closed with a reason is shown with that reason in
// words and what the person can do about it, not as a bare "declined", which
// reads as though they pressed No on their phone.
import assert from "node:assert";
import { readPageSession } from "../dist/pageSession.js";
import { refusalInWords, signInProblem } from "../dist/signInProblem.js";

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
assert.match(signInProblem("declined", "the credential is not accepted here"), /not accepted: the credential is not accepted here\./);
// With no reason the older wording stands.
assert.match(signInProblem("declined"), /Either you declined it on your phone/);
assert.match(signInProblem("declined", "  "), /Either you declined it on your phone/);
// A refusal that leaves the sign-in open (its last_refusal) is said in words too.
assert.equal(refusalInWords("not a member of this asset"), "this Identity Agent is not on this utility app's list of people who may sign in");
assert.match(refusalInWords("no membership resolver for source: employees"), /cannot check/);
console.log("ok");
