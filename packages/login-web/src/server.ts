/**
 * Server-safe entry point (`@identity-agent/login-web/server`).
 *
 * Exposes only the pieces a relying party's BACKEND needs — no React imports,
 * so plain Node/Express/Next-route (or any non-React) backends can depend on
 * it without having React installed.
 */
export { confirmLoginSession } from "./confirmSession.js";
export type { ConfirmSessionOptions, ConfirmedSession } from "./confirmSession.js";
