import type { Express, Request, Response } from "express";
import type { IdentityAgentVerifier } from "./verifier.js";
import type { LoginAssertion } from "./types.js";

export interface MountOptions {
  sessionPath?: string;
  onVerified?: (result: {
    pairwiseAid: string;
    disclosures: Record<string, string>;
    sessionToken: string;
    appSessionToken: string;
  }) => void | Promise<void>;
  issueAppSession?: (pairwiseAid: string, disclosures: Record<string, string>) => string;
}

export function mountIdentityAgentLoginRoutes(
  app: Express,
  verifier: IdentityAgentVerifier,
  opts: MountOptions = {},
): void {
  const base = opts.sessionPath ?? "/auth/ia/session";
  const issueSession =
    opts.issueAppSession ??
    ((pairwiseAid: string) => `ia-session-${pairwiseAid.slice(0, 16)}`);

  app.post(base, async (req: Request, res: Response) => {
    try {
      let origin = process.env.IA_AUDIENCE ?? "http://127.0.0.1:5000";
      if (req.headers["x-forwarded-proto"] && req.headers["x-forwarded-host"]) {
        origin = `${req.headers["x-forwarded-proto"]}://${req.headers["x-forwarded-host"]}`;
      } else if (req.get("host")) {
        origin = `${req.protocol}://${req.get("host")}`;
      }

      const requestedDisclosures: string[] =
        req.body?.requestDisclosures ?? req.body?.requested_disclosures ?? ["display_name", "email"];
      const requestedCredentials = req.body?.requestCredentials ?? req.body?.requested_credentials ?? [];
      const requestScore = req.body?.requestScore ?? req.body?.requested_score;

      const callbackUrl =
        req.body?.callbackUrl ??
        `${origin}/auth/ia/callback`;

      const result = await verifier.createChallenge({
        audience: process.env.IA_AUDIENCE ?? origin,
        requestedDisclosures,
        requestedCredentials,
        requestScore,
        callbackUrl,
      });

      const relayOrQrUrl =
        result.relay_or_qr_url +
        (result.relay_or_qr_url.includes("?") ? "&" : "?") +
        `rp=${encodeURIComponent(origin)}`;

      res.json({
        session_token: result.session_token,
        relay_or_qr_url: relayOrQrUrl,
        qr_url: result.qr_url,
        expires_at: result.expires_at,
      });
    } catch (err) {
      res.status(500).json({ error: (err as Error).message });
    }
  });

  // Minimal Ask pointer: the QR encodes {origin}/i/{token};
  // the IA GETs it to fetch the signed Ask envelope. `/i/` is the one-char Ask
  // namespace, kept off the site's own routes.
  app.get(`/i/:token`, (req: Request, res: Response) => {
    const rec = verifier.sessionStore.get(req.params.token);
    if (!rec) {
      return res.status(404).json({ error: "session not found" });
    }
    res.json(rec.challenge);
  });

  app.get(`${base}/:token`, (req: Request, res: Response) => {
    const state = verifier.getSessionState(req.params.token);
    if (!state) {
      return res.status(404).json({ error: "session not found" });
    }
    res.json({
      state: state.state,
      ...(state.appSessionToken ? { app_session_token: state.appSessionToken } : {}),
    });
  });

  app.post("/auth/ia/callback", async (req: Request, res: Response) => {
    try {
      const assertion = req.body as LoginAssertion;
      const sessionToken = (req.query.session as string) ?? (req.body?.session_token as string);
      if (!sessionToken) {
        return res.status(400).json({ error: "session query param required" });
      }

      const rec = verifier.sessionStore.get(sessionToken);
      if (!rec) {
        return res.status(404).json({ error: "session not found" });
      }
      const token = rec.token;

      const outcome = await verifier.handleCallback(assertion, token, issueSession);
      if (!outcome.ok) {
        return res.status(401).json({ error: outcome.reason });
      }

      const verified = verifier.sessionStore.get(token);
      if (verified?.verifiedResult?.pairwiseAID && verified.appSessionToken && opts.onVerified) {
        await opts.onVerified({
          pairwiseAid: verified.verifiedResult.pairwiseAID,
          disclosures: verified.verifiedResult.disclosures ?? {},
          sessionToken: token,
          appSessionToken: verified.appSessionToken,
        });
      }

      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: (err as Error).message });
    }
  });
}