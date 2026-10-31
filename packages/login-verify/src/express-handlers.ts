import type { IRouter, Request, Response } from "express";
import type { IdentityAgentVerifier } from "./verifier.js";
import type { LoginAssertion } from "./types.js";
import { readAssertion, utf8Text } from "./canonical.js";

const MAX_BODY_BYTES = 1 << 20;

/** The path the Identity Agent posts its assertion to, under wherever the
 *  routes are mounted. */
const CALLBACK_PATH = "/auth/ia/callback";

/** Where the callback's body is kept, as sent, once something has read it. */
const RAW_BODY = Symbol.for("@identity-agent/login-verify raw body");
type WithRawBody = Request & { [RAW_BODY]?: Buffer | Promise<Buffer> };

/** The request's body as sent. Reading it marks it read (`_body`), as a body
 *  parser does, so a parser further along leaves it alone. */
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

/** True for a POST to the sign-in callback, wherever the routes are mounted. */
function isCallback(req: Request): boolean {
  if (req.method !== "POST") return false;
  const path = (req.originalUrl ?? req.url ?? "").split("?")[0].replace(/\/+$/, "");
  return path.endsWith(CALLBACK_PATH);
}

/** Middleware that keeps the sign-in callback's body as sent, so the
 *  assertion in it can be checked from its text. Mount it before any body
 *  parser of your own:
 *
 *      app.use(identityAgentCallbackBody());
 *      app.use(express.json());
 *
 *  It reads only the callback's body and passes every other request on
 *  untouched. An app with no body parser of its own needs neither this nor
 *  `keepLoginRawBody`. */
export function identityAgentCallbackBody() {
  return (req: Request, _res: Response, next: (err?: unknown) => void): void => {
    if (!isCallback(req) || alreadyRead(req) || (req as WithRawBody)[RAW_BODY]) {
      next();
      return;
    }
    readBody(req).then(
      (buf) => {
        (req as WithRawBody)[RAW_BODY] = buf;
        next();
      },
      (err) => next(Object.assign(err instanceof Error ? err : new Error(String(err)), { status: 413 })),
    );
  };
}

/** A body parser `verify` option that keeps the sign-in callback's body as
 *  sent, for an app that would rather keep its own parser first:
 *
 *      app.use(express.json({ verify: keepLoginRawBody }));
 *
 *  Give it to every body parser that could read the callback (by default,
 *  express.json; also express.text or express.raw with a wide `type`). */
export function keepLoginRawBody(req: unknown, _res: unknown, buf: Buffer): void {
  const r = req as WithRawBody;
  if (isCallback(r)) r[RAW_BODY] = Buffer.from(buf);
}

/** What the callback says when the text it needs is gone. */
const RAW_BODY_GONE =
  "a body parser read the assertion before this route could see its text; mount " +
  "identityAgentCallbackBody() before your body parsers, or give them " +
  "{ verify: keepLoginRawBody }";

/** The assertion posted to the callback, read from its text as the core reads
 *  one, so a repeated key, a byte order mark or a whole number spelled 1.0 is
 *  refused. The text comes from `identityAgentCallbackBody` or
 *  `keepLoginRawBody` where the app has a parser, and is read here where it
 *  has none. Where it is gone, the callback is refused rather than checked
 *  from what a lenient parser left. */
async function postedAssertion(req: Request): Promise<LoginAssertion> {
  const kept = (req as WithRawBody)[RAW_BODY];
  if (kept) return readAssertion(utf8Text(await kept));
  if (!alreadyRead(req)) return readAssertion(utf8Text(await readBody(req)));
  throw new Error(RAW_BODY_GONE);
}

/** The options a site's own page posts to start a sign-in, as an object.
 *  Taken from whatever the app's body parsers left (an object from
 *  express.json or express.urlencoded, text from express.text, bytes from
 *  express.raw), and read here where none has run. */
async function sessionOptions(req: Request): Promise<Record<string, any>> {
  let text: string | undefined;
  const kept = (req as WithRawBody)[RAW_BODY];
  if (kept) {
    text = utf8Text(await kept);
  } else if (!alreadyRead(req)) {
    text = utf8Text(await readBody(req));
  } else if (typeof req.body === "string") {
    text = req.body;
  } else if (Buffer.isBuffer(req.body)) {
    text = utf8Text(req.body);
  } else if (req.body === undefined || req.body === null) {
    return {};
  } else if (typeof req.body === "object" && !Array.isArray(req.body)) {
    return req.body as Record<string, any>;
  } else {
    throw new Error("the options must be a JSON object");
  }
  if (text.trim() === "") return {};
  const parsed = JSON.parse(text) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("the options must be a JSON object");
  }
  return parsed as Record<string, any>;
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

/** Mounts the sign-in routes on an app, a Router or a sub-app. The session
 *  route reads its options whatever body parsers the app has. The callback
 *  needs the assertion's text: an app with no body parser of its own needs
 *  nothing more; one with a parser mounts `identityAgentCallbackBody()`
 *  before it, or gives it `{ verify: keepLoginRawBody }`. */
export function mountIdentityAgentLoginRoutes(
  app: IRouter,
  verifier: IdentityAgentVerifier,
  opts: MountOptions = {},
): void {
  const base = opts.sessionPath ?? "/auth/ia/session";
  const issueSession =
    opts.issueAppSession ??
    ((pairwiseAid: string) => `ia-session-${pairwiseAid.slice(0, 16)}`);

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
        `${origin}${req.baseUrl ?? ""}${CALLBACK_PATH}`;

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