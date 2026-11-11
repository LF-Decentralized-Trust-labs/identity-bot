/**
 * The ready-built page for a utility app (`bundle/identity-agent-app.js`, global
 * `IdentityAgentApp`): the sign-in button, the checks of `./app`, the signed
 * calls and sign-out, in one script a page loads with a plain `<script src>`.
 * A page needs no build step, no React and no copy of any of it:
 *
 *   const link = IdentityAgentApp.readAppLink(location.hash);
 *   const session = IdentityAgentApp.appSession(link);
 *   if (!session.held()) IdentityAgentApp.mountSignIn(el, link, session, { onSignedIn, onProblem });
 *   else await session.call("GET", "/session/something");
 *
 * Rebuilt by `npm run bundle`; a test fails when the committed file is not what
 * the sources build.
 */
import React from "react";
import { createRoot } from "react-dom/client";
import { SignInButton } from "./SignInButton.js";
import { appFetch, appSession, readAppLink, SessionEnded, type AppLink, type AppSession } from "./app.js";
import { signInProblem } from "./signInProblem.js";

export { appSession, readAppLink, SessionEnded, signInProblem };

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
