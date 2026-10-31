import type { Express, Request, Response } from "express";
import type { IdentityAgentVerifier } from "./verifier.js";
import type { LoginAssertion } from "./types.js";
import { readAssertion } from "./canonical.js";

const MAX_ASSERTION_BYTES = 1 << 20;

/** The request's body as sent, or null where a body parser the host app
 *  installed has already read it. */
function rawBodyOf(req: Request): Promise<Buffer | null> {
  if ((req as unknown as { _body?: boolean })._body || !req.readable) return Promise.resolve(null);
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_ASSERTION_BYTES) {
        reject(new Error("the assertion is too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

/** The assertion posted to the callback, read as the core reads one. From
 *  the text where it is still there, so a repeated key is refused; where the
 *  host app's JSON parser has already read the body, only what survives
 *  parsing can be checked, which leaves a repeated key unseen. Mount these
 *  routes before a global JSON parser to keep that check. */
async function postedAssertion(req: Request): Promise<LoginAssertion> {
  const raw = await rawBodyOf(req);
  if (raw) return readAssertion(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  if (typeof req.body === "string") return readAssertion(req.body);
  if (Buffer.isBuffer(req.body)) return readAssertion(new TextDecoder("utf-8", { fatal: true }).decode(req.body));
  return req.body as LoginAssertion;
}

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
      // The session is named in the query, as an Identity Agent posts it: the
      // body is the assertion and nothing else.
      const sessionToken = req.query.session as string | undefined;
      if (!sessionToken) {
        return res.status(400).json({ error: "session query param required" });
      }
      let assertion: LoginAssertion;
      try {
        assertion = await postedAssertion(req);
      } catch (err) {
        return res.status(400).json({ error: `the assertion cannot be read: ${(err as Error).message}` });
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