/**
 * Starting a sign-in from a relying party's BACKEND.
 *
 * The site's server asks its organisation's Identity Agent for a sign-in on one
 * of the organisation's website assets. The Identity Agent signs the challenge
 * with the asset's key, which never leaves it, and hands back what the site
 * shows the person (a pointer to scan) plus a secret that only the site's
 * server keeps. The server later confirms the result with `confirmLoginSession`,
 * passing that secret. Keep the secret out of the page and out of any link.
 *
 * Framework-agnostic: plain fetch.
 */

export interface StartSessionOptions {
  /** The organisation's Identity Agent base URL, e.g. https://ia.example.com */
  agentUrl: string;
  /** The website asset the organisation created for this site. */
  assetId: string;
  /** The site's own origin, e.g. https://portal.example.com. The person's
   *  approval is for this audience and no other. */
  audience: string;
  /** What the site asks the person to share. */
  requestDisclosures?: string[];
  /** The thumbprint of a key the person's browser holds, when the sign-in is
   *  for that key (ADR-066). */
  browserKey?: string;
  fetchFn?: typeof fetch;
}

export interface StartedSession {
  /** Names the sign-in; travels in the pointer. */
  sessionToken: string;
  /** What to show the person: scanning it opens the sign-in in their Identity Agent. */
  pointerUrl: string;
  /** Keep on the server. Required by `confirmLoginSession` to read who signed in. */
  collectorSecret: string;
}

export async function startLoginSession(opts: StartSessionOptions): Promise<StartedSession> {
  const base = opts.agentUrl.replace(/\/$/, "");
  const f = opts.fetchFn ?? fetch;
  const resp = await f(`${base}/api/login/session/${encodeURIComponent(opts.assetId)}`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({
      audience: opts.audience,
      requestDisclosures: opts.requestDisclosures ?? [],
      ...(opts.browserKey ? { browserKey: opts.browserKey } : {}),
    }),
  });
  if (!resp.ok) {
    const why = (await resp.text().catch(() => "")).trim();
    throw new Error(`login: the Identity Agent at ${base} would not start a sign-in (${resp.status}${why ? `: ${why}` : ""})`);
  }
  const out = (await resp.json()) as {
    session_token?: string;
    relay_or_qr_url?: string;
    collector_secret?: string;
  };
  if (!out.session_token || !out.relay_or_qr_url || !out.collector_secret) {
    throw new Error(`login: the Identity Agent at ${base} answered a sign-in without a token, pointer and secret`);
  }
  return {
    sessionToken: out.session_token,
    pointerUrl: out.relay_or_qr_url,
    collectorSecret: out.collector_secret,
  };
}
