/** What a person can do about a refused answer. "again": approve the sign-in again, it may go through.
 *  "owner": nothing they can do here changes it, so it is for the utility app's owner. */
export type RefusalNextStep = "again" | "owner";

interface Said {
  words: string;
  next: RefusalNextStep;
  /** What to do, where the step's usual wording does not fit. */
  todo?: string;
}

/** Every reason the Identity Agent's core keeps as a refused answer's `last_refusal` (its login handlers'
 *  answer check, enrolment-policy and credential gates, and the owner's front-end setting), said in words.
 *  These are the core's fixed wordings; nothing here says more than the reason itself does. */
const REFUSALS: Record<string, Said> = {
  "an answer could not be verified, and was not accepted": {
    words: "an answer to this sign-in could not be confirmed as coming from your Identity Agent",
    next: "again",
  },
  "asset store unavailable": {
    words: "the owner's Identity Agent could not read this utility app's settings",
    next: "again",
  },
  "the website's settings could not be read": {
    words: "the owner's Identity Agent could not read this utility app's settings",
    next: "again",
  },
  "asset not found": {
    words: "this utility app is not set up on its owner's Identity Agent",
    next: "owner",
  },
  "not a member of this asset": {
    words: "your Identity Agent is not on this utility app's list of people who may sign in",
    next: "owner",
    todo: "Ask the utility app's owner to add you; trying again will not help until they do.",
  },
  "the required credential was not presented": {
    words: "this utility app asks for a credential your Identity Agent did not present",
    next: "owner",
    todo: "Approve it again from an Identity Agent that holds that credential, or ask the utility app's owner which credential it needs.",
  },
  "the credential could not be checked": {
    words: "the credential your Identity Agent presented could not be checked",
    next: "again",
  },
  "the credential is not accepted here": {
    words: "the credential your Identity Agent presented is not one this utility app accepts",
    next: "owner",
    todo: "Ask the utility app's owner which credential it accepts; trying again with the same one will not help.",
  },
  "minimum score gate is not available yet": {
    words: "this utility app asks for a minimum score, which cannot be checked yet",
    next: "owner",
  },
  "badge gate is not available yet": {
    words: "this utility app asks for a badge, which cannot be checked yet",
    next: "owner",
  },
  "assurance level gate is not available yet": {
    words: "this utility app asks for an assurance level, which cannot be checked yet",
    next: "owner",
  },
  "the owner's front-end setting could not be read": {
    words: "the owner's Identity Agent could not read which ways of signing in to this utility app are switched on",
    next: "again",
  },
  "this sign-in does not say which front end it is for, 'browser' or 'installed_app'": {
    words: "this sign-in did not say whether it came from a browser or an installed copy of the utility app",
    next: "owner",
  },
};

const FRONT_END = { browser: "a browser", "installed-app": "an installed copy of it" } as const;

function said(reason: string): Said | undefined {
  const r = reason.trim();
  if (REFUSALS[r]) return REFUSALS[r];
  if (r.startsWith("no membership resolver for source")) {
    return {
      words: "the list of people who may sign in to this utility app is one its owner's Identity Agent cannot check",
      next: "owner",
    };
  }
  let m = /^this utility app does not offer a (browser|installed-app) front end$/.exec(r);
  if (m) {
    return { words: "this utility app cannot be signed in to from " + FRONT_END[m[1] as keyof typeof FRONT_END], next: "owner" };
  }
  m = /^the owner of this utility app has switched off its (browser|installed-app) front end$/.exec(r);
  if (m) {
    return {
      words: "the owner of this utility app has switched off signing in from " + FRONT_END[m[1] as keyof typeof FRONT_END],
      next: "owner",
      todo: "Sign in another way the owner allows, or ask the owner to switch this one back on; trying again here will not help.",
    };
  }
  return undefined;
}

/** A refusal reason from the Identity Agent, in words a person can act on. A reason not known here is shown as it
 *  was said, never hidden. */
export function refusalInWords(reason: string): string {
  return said(reason)?.words ?? reason.trim();
}

/** Whether approving the sign-in again can help ("again"), or only the utility app's owner can ("owner"). A reason
 *  not known here is taken as one a retry may get past. */
export function refusalNextStep(reason: string): RefusalNextStep {
  return said(reason)?.next ?? "again";
}

/** The line a page shows while a sign-in is still open after an answer was refused (its `lastRefusal`): why, in
 *  words, and what the person can do about it. */
export function refusalProblem(reason: string): string {
  const s = said(reason);
  const todo = s?.todo ??
    (s?.next === "owner"
      ? "Trying again will not help until the utility app's owner changes this; tell them."
      : "The sign-in is still open, so you can approve it again. If it keeps happening, tell the utility app's owner.");
  return "That answer was refused: " + refusalInWords(reason) + ". " + todo;
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
  return "The sign-in was not accepted: " + refusalInWords(reason) + ". " + (refusalNextStep(reason) === "owner"
    ? "Pressing the button again will not help until the utility app's owner changes this; tell them."
    : "Press the button to try again; if it keeps happening, tell the utility app's owner.");
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

/** What a sign-in page tells its person when polling stops, from what the poll read: a decline is said with the
 *  Identity Agent's reason for it, anything else with the error the poll met. */
export function pollProblem(poll: { state: "declined" | "expired" | "error"; reason?: string; error?: string }): string {
  return signInProblem(poll.state, poll.state === "declined" ? poll.reason : poll.error);
}
