/**
 * React-free entry point (`@identity-agent/login-web/page`) for a web page that
 * has only the login SDK and no back end of its own. See pageSession.ts.
 */
export { startPageSession, readPageSession } from "./pageSession.js";
export type { PageSessionStart, PageSessionRead } from "./pageSession.js";
