/**
 * Server-side confirmation for widget-mode relying parties.
 *
 * The SignInButton completes in the BROWSER — an RP must never issue its own
 * session from that alone. Before setting a session cookie, the RP's backend
 * calls this to confirm the login state directly with the Identity Agent
 * (the same widget endpoint family the button uses, server-to-server).
 *
 * Framework-agnostic: plain fetch, no React — import from
 * `@identity-agent/login-web/server` so non-React backends can use it too.
 */

export interface ConfirmSessionOptions {
  /** Identity Agent base URL, e.g. https://ia.example.com */
  agentUrl: string;
  /** The asset id the widget was pointed at. */
  assetId: string;
  /** The session token handed to onSuccess (or being polled). */
  sessionToken: string;
  /** Handed to the browser that created the session, and passed back here.
   *  Without it the Identity Agent reports the state but withholds who signed
   *  in, because the session token alone travels in the QR code. */
  collectorSecret?: string | null;
  /** Optional fetch override (testing / custom agents). */
  fetchFn?: typeof fetch;
  /** Spends a verified session so the same one signs nobody in twice. Without
   *  it, anybody holding this session's token and your secret's response can
   *  have it confirmed again for as long as the Identity Agent keeps it; a
   *  site that issues its own session on `verified` should pass one. Any store
   *  of the shape `inMemoryConsumedNonces()` in `@identity-agent/login-verify`
   *  returns will do; a site on more than one process shares one. */
  consume?: { claim(key: string): Promise<boolean> | boolean };
}

export type ConfirmedSession =
  | {
      state: "verified";
      pairwiseAid: string;
      disclosures?: Record<string, unknown>;
      /** Membership-admitted logins: who the admitting roster says this is
       * (carried in the Identity Agent's login result) — e.g. role + display
       * name. RPs use this instead of querying org-internal rosters. */
      memberInfo?: { role?: string; displayName?: string };
    }
  | { state: "declined"; reason?: string }
  | { state: "pending" };

/**
 * Confirm a widget login session with the Identity Agent.
 *
 * Returns `verified` (with the verified pairwise AID — the identity the IA
 * checked the signed assertion and admission policy for), `declined`, or
 * `pending`. Only issue an application session on `verified`.
 */
export async function confirmLoginSession(opts: ConfirmSessionOptions): Promise<ConfirmedSession> {
  const base = opts.agentUrl.replace(/\/$/, "");
  const f = opts.fetchFn ?? fetch;
  const resp = await f(
    `${base}/api/login/session/${encodeURIComponent(opts.assetId)}/${encodeURIComponent(opts.sessionToken)}`,
    {
      headers: {
        accept: "application/json",
        ...(opts.collectorSecret ? { "X-Collector-Secret": opts.collectorSecret } : {}),
      },
    },
  );
  if (!resp.ok) return { state: "pending" };
  const body = (await resp.json()) as {
    state?: string;
    app_session_token?: string;
    disclosures?: Record<string, unknown>;
    member_info?: { role?: string; display_name?: string };
    reason?: string;
    identity_withheld?: boolean;
  };
  // Verified, but this caller could not collect. Reporting it as pending would
  // spin forever; reporting it as verified would hand back an empty identity.
  if (body.state === "verified" && body.identity_withheld) {
    throw new Error(
      "login: the Identity Agent withheld the identity — pass the collectorSecret returned when the session was created",
    );
  }
  if (body.state === "verified" && body.app_session_token) {
    if (opts.consume) {
      const fresh = await opts.consume.claim(`${base}|${opts.assetId}|${opts.sessionToken}`);
      if (!fresh) throw new Error("login: this sign-in has already been used");
    }
    return {
      state: "verified",
      pairwiseAid: body.app_session_token,
      disclosures: body.disclosures,
      memberInfo: body.member_info
        ? { role: body.member_info.role, displayName: body.member_info.display_name }
        : undefined,
    };
  }
  if (body.state === "declined") return { state: "declined", reason: body.reason };
  return { state: "pending" };
}
