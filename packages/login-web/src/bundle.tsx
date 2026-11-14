/**
 * The ready-built page for a utility app (`identity-agent-app.js` built by `npm run build:app`, global
 * `IdentityAgentApp`): the sign-in button, the checks of `./app`, the signed
 * calls and sign-out, in one script a page loads with a plain `<script src>`.
 * A page needs no build step, no React and no copy of any of it:
 *
 *   const pin = await IdentityAgentApp.loadPinnedApp();   // the page's own config.json (or readPinnedApp(parsed))
 *   const link = IdentityAgentApp.readAppLink(location.hash, pin);   // or, with no link: await pinnedAppLink(pin)
 *   const session = IdentityAgentApp.appSession(link);
 *   if (!session.held()) IdentityAgentApp.mountSignIn(el, link, session, { onSignedIn, onProblem });
 *   else await session.call("GET", "/session/something");
 *
 * The page signs in only to the app its own published `config.json` pins (`loadPinnedApp`): `readAppLink`
 * here is the pinned read (`readPinnedAppLink`), so a link naming another app, relay identifier or back end
 * is refused, and a page with no pin signs nobody in.
 *
 * Built by `npm run build:app`, never committed; a test fails when what it writes
 * lacks what a page uses.
 */
import React from "react";
import { createRoot } from "react-dom/client";
import { SignInButton } from "./SignInButton.js";
import { appFetch, appSession, loadPinnedApp, pinnedAppLink, readPinnedApp, readPinnedAppLink, SessionEnded, type AppLink, type AppSession } from "./app.js";
import { signInProblem } from "./signInProblem.js";
import { signPersonStatement } from "./personStatement.js";

// A hosted page has no unpinned read of a link: `readAppLink` is the pinned one.
export { appSession, loadPinnedApp, pinnedAppLink, readPinnedApp, readPinnedAppLink as readAppLink, readPinnedAppLink, SessionEnded, signInProblem, signPersonStatement };

export interface SignInHandlers {
  /** The person approved and the session is kept; call the app as them now. */
  onSignedIn(): void;
  /** A sentence to show the person: what happened and what to do. */
  onProblem(text: string): void;
}

/** Draws the sign-in button in `el`. Checks the link's key log first and tells
 *  `onProblem` why when the link is not one to trust. */
export async function mountSignIn(el: HTMLElement, link: AppLink, session: AppSession, h: SignInHandlers): Promise<void> {
  let app;
  try {
    app = await appFetch(link, { browserKey: () => session.key() });
  } catch (e) {
    h.onProblem((e as Error).message);
    return;
  }
  createRoot(el).render(
    <SignInButton
      sessionEndpoint={app.sessionEndpoint}
      fetchFn={app.fetchFn}
      browserKey={app.browserKey}
      frontEnd="browser"
      sameDeviceProbe={false}
      requestDisclosures={[]}
      onSuccess={({ appSessionToken }) => {
        if (!appSessionToken) return h.onProblem(signInProblem("error"));
        session.keep(appSessionToken);
        h.onSignedIn();
      }}
      onError={(e) => h.onProblem(e.message)}
    />,
  );
}
