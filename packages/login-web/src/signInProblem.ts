/** What a person is told, in words, when a sign-in stops: what happened and what
 *  to do. `detail` is whatever the Identity Agent or the utility app said. */
export function signInProblem(state: "declined" | "expired" | "error", detail?: string): string {
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
