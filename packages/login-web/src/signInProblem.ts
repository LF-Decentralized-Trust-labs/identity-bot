/** A refusal reason from the Identity Agent, in words a person can act on. The reasons it gives are short and are the
 *  words of its own code ("not a member of this asset"); a reason not known here is shown as it was said, never hidden. */
export function refusalInWords(reason: string): string {
  const r = reason.trim();
  if (r === "not a member of this asset") {
    return "this Identity Agent is not on this utility app's list of people who may sign in";
  }
  if (r.startsWith("no membership resolver for source")) {
    return "the list of people who may sign in to this utility app is one its owner's Identity Agent cannot check";
  }
  return r;
}

/** A sign-in the Identity Agent closed with a reason, said with what the person can do about it. The reasons are the
 *  core's own (its login handlers' "denied" sign-ins); a reason not known here is shown as it was said. */
function declinedInWords(reason: string): string {
  switch (reason) {
    case "the asset this sign-in was for is gone":
      return "The sign-in was not accepted: this utility app is no longer set up on its owner's Identity Agent, so nobody can sign in to it. Tell the utility app's owner.";
    case "the installed app's key was not proved for this sign-in":
      return "The sign-in was not accepted: the Identity Agent could not confirm the key of this installed copy of the utility app for this sign-in. Press the button to try again.";
    case "this key already speaks for another person":
      return "The sign-in was not accepted: the key this browser signs with already signs in another person to this utility app. Sign in from another browser.";
    case "the sign-in could not be recorded":
      return "The sign-in was not accepted: the Identity Agent could not record it. Press the button to try again.";
  }
  return "The sign-in was not accepted: " + refusalInWords(reason) + ". Press the button to try again; if it keeps happening, tell the utility app's owner.";
}

/** What a person is told, in words, when a sign-in stops: what happened and what
 *  to do. `detail` is whatever the Identity Agent or the utility app said. */
export function signInProblem(state: "declined" | "expired" | "error", detail?: string): string {
  if (state === "declined" && detail && detail.trim()) {
    return declinedInWords(detail.trim());
  }
  if (state === "declined") {
    return "The sign-in was not accepted. Either you declined it on your phone, or this Identity Agent is not on this utility app's list of people who may sign in. " +
      "Ask the utility app's owner to add you, then press the button to try again.";
  }
  if (state === "expired") {
    return "The sign-in ran out of time before it was approved on your phone. Press the button to start a new one.";
  }
  const d = detail ?? "";
  if (/\b(401|403)\b/.test(d)) return "The utility app did not accept this browser's sign-in. Press the button to try again; if it keeps happening, ask the utility app's owner.";
  if (/\b(502|503|504)\b/.test(d) || /Failed to fetch|NetworkError/i.test(d)) {
    return "The utility app cannot be reached right now. Check that it is running (its owner can check), then press the button to try again.";
  }
  return d || "The sign-in did not complete. Press the button to try again.";
}
