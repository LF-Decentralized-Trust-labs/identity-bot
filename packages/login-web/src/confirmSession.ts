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
  /** Optional fetch override (testing / custom agents). */
  fetchFn?: typeof fetch;
}

export type ConfirmedSession =
  | { state: "verified"; pairwiseAid: string; disclosures?: Record<string, unknown> }
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
    { headers: { accept: "application/json" } },
  );
  if (!resp.ok) return { state: "pending" };
  const body = (await resp.json()) as {
    state?: string;
    app_session_token?: string;
    disclosures?: Record<string, unknown>;
    reason?: string;
  };
  if (body.state === "verified" && body.app_session_token) {
    return { state: "verified", pairwiseAid: body.app_session_token, disclosures: body.disclosures };
  }
  if (body.state === "declined") return { state: "declined", reason: body.reason };
  return { state: "pending" };
}
