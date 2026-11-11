/**
 * A sign-in from a web page that has no back end of its own (`@identity-agent/login-web/page`).
 *
 * The page talks to the website owner's Identity Agent on its public login
 * routes only: it starts a sign-in on the owner's website asset, shows the
 * person the pointer, and reads the answer with the secret only it was given.
 * This is a sign-in to a website asset, never access to an identity. The same
 * two functions drive the React button, so a page without React uses exactly
 * what the button does.
 *
 * The page does not name its own audience. The Identity Agent takes it from the
 * `Origin` the browser sends, which a page's script cannot set.
 *
 * Plain fetch, no React.
 */

export interface PageSessionStart {
  sessionToken: string;
  /** What to show the person: scanning it opens the sign-in in their Identity Agent. */
  pointerUrl: string;
  /** The address to show as a QR code (the pointer unless the agent says otherwise). */
  qrUrl: string;
  /** Kept by this page, and sent with every read. Never put it in a link or a QR code. */
  collectorSecret: string | null;
}

export async function startPageSession(opts: {
  /** `{agent}/api/login/session/{asset_id}` */
  sessionEndpoint: string;
  body?: Record<string, unknown>;
  fetchFn?: typeof fetch;
}): Promise<PageSessionStart> {
  const f = opts.fetchFn ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
  const resp = await f(opts.sessionEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(opts.body ?? {}),
  });
  if (!resp.ok) throw new Error(`session create failed: ${resp.status}`);
  const data = (await resp.json()) as {
    session_token?: string;
    relay_or_qr_url?: string;
    qr_url?: string;
    collector_secret?: string;
  };
  if (!data.session_token || !(data.relay_or_qr_url ?? data.qr_url)) {
    throw new Error("session create failed: the Identity Agent answered without a token and a pointer");
  }
  return {
    sessionToken: data.session_token,
    pointerUrl: (data.relay_or_qr_url ?? data.qr_url) as string,
    qrUrl: (data.qr_url ?? data.relay_or_qr_url) as string,
    collectorSecret: data.collector_secret ?? null,
  };
}

export interface PageSessionRead {
  /** The Identity Agent's own word for it: connecting, connected, scanned, verified, declined, expired. */
  state: string;
  /** Who signed in (their pairwise identifier), on `verified`, to the holder of the secret, once. */
  appSessionToken?: string;
  disclosures?: Record<string, unknown>;
  /** The signed assertion the person's Identity Agent sent, as text, handed with
   *  the identity and only once. Check it in the page with `checkSignInInPage`
   *  from `@identity-agent/login-verify/browser`. */
  assertion?: string;
  /** The nonce and the site the challenge was signed for, to check it against. */
  nonce?: string;
  siteAid?: string;
  browserKey?: string;
  frontEnd?: string;
  reason?: string;
  /** Why the last answer was refused while the sign-in is still open, so the person can fix it and try again. */
  lastRefusal?: string;
  /** Verified, but this caller was not given the identity: it has lost its secret, or already read it. */
  identityWithheld?: boolean;
}

export async function readPageSession(opts: {
  sessionEndpoint: string;
  sessionToken: string;
  collectorSecret?: string | null;
  fetchFn?: typeof fetch;
}): Promise<PageSessionRead> {
  const f = opts.fetchFn ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
  const resp = await f(`${opts.sessionEndpoint}/${encodeURIComponent(opts.sessionToken)}`, {
    headers: opts.collectorSecret ? { "X-Collector-Secret": opts.collectorSecret } : undefined,
  });
  if (!resp.ok) throw new Error(`poll ${resp.status}`);
  const d = (await resp.json()) as Record<string, unknown>;
  return {
    state: String(d.state ?? "connecting"),
    appSessionToken: d.app_session_token as string | undefined,
    disclosures: d.disclosures as Record<string, unknown> | undefined,
    assertion: d.assertion as string | undefined,
    nonce: d.nonce as string | undefined,
    siteAid: d.site_aid as string | undefined,
    browserKey: d.browser_key as string | undefined,
    frontEnd: d.front_end as string | undefined,
    reason: d.reason as string | undefined,
    lastRefusal: d.last_refusal as string | undefined,
    identityWithheld: d.identity_withheld === true ? true : undefined,
  };
}
