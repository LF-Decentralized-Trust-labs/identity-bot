import type { Express, Request, Response } from "express";
import type { IdentityAgentVerifier } from "./verifier.js";
import type { LoginAssertion } from "./types.js";
import { readAssertion, utf8Text } from "./canonical.js";

const MAX_BODY_BYTES = 1 << 20;

/** Where the callback's body is kept once it has been read as sent. */
const RAW_BODY = Symbol("identity-agent raw body");
type WithRawBody = Request & { [RAW_BODY]?: Promise<Buffer> };

/** The request's body as sent. Reading it marks it read (`_body`), as a body
 *  parser does, so a JSON parser further along leaves it alone. */
function readBody(req: Request): Promise<Buffer> {
  (req as unknown as { _body?: boolean })._body = true;
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("the body is too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

/** True where a body parser has already consumed the request. */
function alreadyRead(req: Request): boolean {
  return Boolean((req as unknown as { _body?: boolean })._body) || !req.readable;
}

/** The assertion posted to the callback, read from its text as the core reads
 *  one, so a repeated key, a byte order mark or a whole number spelled 1.0 is
 *  refused. The text is captured ahead of any JSON parser the host app
 *  installed (`readCallbackBodyFirst`); were it ever gone, the callback is
 *  refused rather than checked from what a lenient parser left. */
async function postedAssertion(req: Request): Promise<LoginAssertion> {
  const kept = (req as WithRawBody)[RAW_BODY];
  if (kept) return readAssertion(utf8Text(await kept));
  if (!alreadyRead(req)) return readAssertion(utf8Text(await readBody(req)));
  throw new Error("the body was read by another parser before this route saw its text");
}

/** The options a site's own page posts to start a sign-in. Taken from the
 *  host app's JSON parser where one has run, and read here where none has. */
async function sessionOptions(req: Request): Promise<Record<string, any>> {
  if (alreadyRead(req)) {
    return req.body && typeof req.body === "object" ? req.body : {};
  }
  const raw = await readBody(req);
  if (raw.length === 0) return {};
  const parsed = JSON.parse(utf8Text(raw)) as unknown;
  return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, any>) : {};
}

/** Puts a reader for the callback's body at the front of the app's
 *  middleware, so it holds the text before any JSON parser the app installed,
 *  whether that was mounted before these routes or after. It reads only the
 *  callback's body and then hands the request on, so everything else the app
 *  mounted still runs in its order. */
function readCallbackBodyFirst(app: Express, path: string): void {
  app.use(path, (req: Request, _res: Response, next: () => void) => {
    // Only the callback itself, not a route of the app's that happens to sit
    // beneath its path.
    if (req.method === "POST" && req.path === "/" && !alreadyRead(req)) {
      const body = readBody(req);
      body.catch(() => undefined); // surfaced by the route, as a 400
      (req as WithRawBody)[RAW_BODY] = body;
    }
    next();
  });
  // Express 4 keeps its middleware in app._router.stack (Express 5 in
  // app.router.stack). The layer just added is the last; it moves to just
  // after Express's own request set-up, ahead of the app's.
  const anyApp = app as unknown as { _router?: { stack?: unknown[] }; router?: { stack?: unknown[] } };
  const stack = (anyApp._router ?? anyApp.router)?.stack;
  if (!Array.isArray(stack)) return;
  const layer = stack.pop();
  let at = 0;
  while (at < stack.length && ["query", "expressInit"].includes((stack[at] as { name?: string }).name ?? "")) at++;
  stack.splice(at, 0, layer);
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

const CALLBACK_PATH = "/auth/ia/callback";

/** Mounts the sign-in routes. They work wherever they are mounted relative to
 *  the app's own body parsers: the session route takes its options from the
 *  app's JSON parser or reads them itself, and the callback's text is read
 *  ahead of any parser, so the assertion in it is checked as sent. */
export function mountIdentityAgentLoginRoutes(
  app: Express,
  verifier: IdentityAgentVerifier,
  opts: MountOptions = {},
): void {
  const base = opts.sessionPath ?? "/auth/ia/session";
  const issueSession =
    opts.issueAppSession ??
    ((pairwiseAid: string) => `ia-session-${pairwiseAid.slice(0, 16)}`);

  readCallbackBodyFirst(app, CALLBACK_PATH);

  app.post(base, async (req: Request, res: Response) => {
    try {
      let body: Record<string, any>;
      try {
        body = await sessionOptions(req);
      } catch (err) {
        return res.status(400).json({ error: `the request cannot be read: ${(err as Error).message}` });
      }
      let origin = process.env.IA_AUDIENCE ?? "http://127.0.0.1:5000";
      if (req.headers["x-forwarded-proto"] && req.headers["x-forwarded-host"]) {
        origin = `${req.headers["x-forwarded-proto"]}://${req.headers["x-forwarded-host"]}`;
      } else if (req.get("host")) {
        origin = `${req.protocol}://${req.get("host")}`;
      }

      const requestedDisclosures: string[] =
        body.requestDisclosures ?? body.requested_disclosures ?? ["display_name", "email"];
      const requestedCredentials = body.requestCredentials ?? body.requested_credentials ?? [];
      const requestScore = body.requestScore ?? body.requested_score;

      const callbackUrl =
        body.callbackUrl ??
        `${origin}${CALLBACK_PATH}`;

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

  app.post(CALLBACK_PATH, async (req: Request, res: Response) => {
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