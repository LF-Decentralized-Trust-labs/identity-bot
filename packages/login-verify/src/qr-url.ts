/** True when the RP session API shares the same origin as the site OOBI URL. */
export function isRpHostedOobi(oobiUrl: string): boolean {
  try {
    const path = new URL(oobiUrl).pathname;
    return path.includes("/auth/ia/site/oobi/");
  } catch {
    return false;
  }
}

/**
 * Minimal login QR payload: a bare `request_uri` pointer to the
 * signed challenge bundle. It carries ONLY the cross-device correlation handle
 * (the session token, in the path) — the one thing the QR must convey so the
 * phone's response binds back to the waiting browser session. The host IS the
 * RP origin (== `audience`), so no `rp` param is needed; everything else
 * (site AID, OOBI, nonce, requested disclosures) lives in the signed bundle the
 * IA fetches from this URL after scanning.
 *
 * Example: `https://rp.example/i/Joy6X61xwxdQhhQ`
 *
 * `/i/` is the one-char Ask namespace (keeps the pointer off the site's own
 * routes); the path segment is the session token. The IA fetches this URL to
 * get the signed Ask envelope and dispatches on the Ask's `t` (action).
 */
export function buildLoginQrUrl(
  rpOrigin: string,
  sessionToken: string,
  namespace = "/i",
): string {
  const origin = rpOrigin.replace(/\/+$/, "");
  const ns = namespace.startsWith("/") ? namespace : `/${namespace}`;
  return `${origin}${ns}/${sessionToken}`;
}