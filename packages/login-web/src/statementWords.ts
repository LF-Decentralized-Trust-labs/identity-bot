/**
 * What a person is told while a statement they were asked to sign is with their own device
 * (`signStatement`, ADR-080). Every state says in plain words that the signing happens on their own
 * device, and none is a bare spinner. The words live here, apart from the screen that draws them, so
 * a test can assert them and a page that draws its own screen says the same things.
 */

/** Where a statement asked of a person stands, as the page's screen is told. */
export type StatementView =
  | { state: "pointer"; pointer: string; statement: string }
  | { state: "waiting"; pointer: string; statement: string }
  | { state: "scanned"; pointer: string; statement: string }
  | { state: "signed" }
  | { state: "declined" }
  | { state: "expired" }
  | { state: "error"; reason: string };

export interface StatementWords {
  title: string;
  body: string;
  /** What the person may press, by name: cancel, again. */
  actions: Array<"cancel" | "again">;
  /** The label of each action, in these words. */
  labels: Record<string, string>;
}

const LABELS = { cancel: "Cancel", again: "Try again", start: "Start again", close: "Close" };

export function statementWords(v: StatementView): StatementWords {
  switch (v.state) {
    case "pointer":
      return {
        title: "Sign on your own device.",
        body: "Scan this code with the Identity Agent on your phone, or press Copy link instead and paste the link into the Identity Agent app on this computer. The statement you are asked to sign is shown below, so you can compare it with what your device shows.",
        actions: ["cancel"],
        labels: LABELS,
      };
    case "waiting":
      return {
        title: "Waiting for your phone or computer.",
        body: "Nothing is signed until you approve on it. The code stays here until you do.",
        actions: ["cancel"],
        labels: LABELS,
      };
    case "scanned":
      return {
        title: "Your device has the request.",
        body: "Check the statement on its screen, then Approve or Deny there.",
        actions: ["cancel"],
        labels: LABELS,
      };
    case "signed":
      return { title: "Signed on your device.", body: "Carrying on.", actions: [], labels: LABELS };
    case "declined":
      return {
        title: "You declined on your device.",
        body: "Nothing was signed. Try again to get a new code.",
        actions: ["again", "cancel"],
        labels: { ...LABELS, cancel: "Close" },
      };
    case "expired":
      return {
        title: "This request expired before it was signed.",
        body: "Nothing was signed. Start again to get a new code.",
        actions: ["again", "cancel"],
        labels: { ...LABELS, again: "Start again", cancel: "Close" },
      };
    case "error":
      return { title: "This could not be signed.", body: v.reason, actions: ["cancel"], labels: { ...LABELS, cancel: "Close" } };
  }
}

/** The sentence for why a statement could not be started or read, by the status the app answered,
 *  for the reasons the app does not say itself. Never a bare status code. */
export function statementProblem(status: number, said?: string): string {
  if (said) return said;
  if (status === 403) return "This app has not been given the right to ask you to sign. Ask the app's owner.";
  if (status === 400) return "The statement could not be asked for as written.";
  if (status === 429) return "Too many statements are waiting to be signed. Try again in a few minutes.";
  if (status === 502 || status === 503 || status === 504) {
    return "The app could not be reached, or could not reach your organisation's Identity Agent. Try again in a moment.";
  }
  return "The statement could not be asked for. Try again.";
}
