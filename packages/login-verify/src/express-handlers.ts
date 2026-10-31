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

/** A body larger than a sign-in sends, answered 413. */
class BodyTooLarge extends Error {
  constructor() {
    super(`the body is larger than ${MAX_BODY_BYTES} bytes`);
  }
}

/** The request's body as sent. Reading it marks it read (`_body`), as a body
 *  parser does, so a parser further along leaves it alone. A body over the
 *  limit stops being read and is refused with BodyTooLarge; the socket is
 *  left alone so the 413 can be sent, and Node closes the connection after
 *  it because the rest of the body was never read. */
function readBody(req: Request): Promise<Buffer> {
  (req as unknown as { _body?: boolean })._body = true;
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const onData = (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        stop();
        req.pause();
        reject(new BodyTooLarge());
        return;
      }
      chunks.push(c);
    };
    const onEnd = () => {
      stop();
      resolve(Buffer.concat(chunks));
    };
    const onError = (err: Error) => {
      stop();
      reject(err);
    };
    const stop = () => {
      req.off("data", onData);
      req.off("end", onEnd);
      req.off("error", onError);
    };
    req.on("data", onData);
    req.on("end", onEnd);
    req.on("error", onError);
  });
}

/** The status to answer a body that could not be read with. */
function unreadableStatus(err: unknown): number {
  return err instanceof BodyTooLarge ? 413 : 400;
}

/** True where a body parser has already consumed the request. */
function alreadyRead(req: Request): boolean {
  return Boolean((req as unknown as { _body?: boolean })._body) || !req.readable;
}

export interface CallbackBodyOptions {
  /** The callback's full path as the app serves it: "/auth/ia/callback"
   *  (the default) where the routes are mounted at the top, or with the
   *  prefix they are mounted under, "/login/auth/ia/callback". Only a POST
   *  to exactly this path is read. */
  path?: string;
  /** As Express's own "case sensitive routing": false by default, so
   *  "/Auth/IA/Callback" is the same path, as Express routes it. */
  caseSensitive?: boolean;
  /** As Express's own "strict routing": false by default, so one trailing
   *  slash is the same path, as Express routes it. */
  strict?: boolean;
}

/** Middleware that keeps the sign-in callback's body as sent, so the
 *  assertion in it can be checked from its text. Mount it before any body
 *  parser of your own:
 *
 *      app.use(identityAgentCallbackBody());
 *      app.use(express.json());
 *
 *  Where the routes are mounted under a prefix, name the callback's full
 *  path: `identityAgentCallbackBody({ path: "/login/auth/ia/callback" })`.
 *  It reads only a POST to that path, matched by Express's own rules, and
 *  passes every other request on untouched. A body over 1 MiB is answered
 *  413. An app with no body parser of its own needs neither this nor
 *  `keepLoginRawBody`. */
export function identityAgentCallbackBody(options: CallbackBodyOptions = {}) {
  const fold = (p: string) => (options.caseSensitive ? p : p.toLowerCase());
  const want = fold(options.path ?? CALLBACK_PATH);
  const matches = (req: Request): boolean => {
    if (req.method !== "POST") return false;
    let path = fold((req.originalUrl ?? req.url ?? "").split("?")[0]);
    if (!options.strict && path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);
    return path === want;
  };
  return (req: Request, res: Response, next: (err?: unknown) => void): void => {
    if (!matches(req) || alreadyRead(req) || (req as WithRawBody)[RAW_BODY]) {
      next();
      return;
    }
    readBody(req).then(
      (buf) => {
        (req as WithRawBody)[RAW_BODY] = buf;
        next();
      },
      (err) => {
        // Answered here, as the route answers it, rather than handed to the
        // app's error handler, which may not know what a 413 is for.
        if (err instanceof BodyTooLarge) res.setHeader("Connection", "close");
        res.status(unreadableStatus(err)).json({ error: `the assertion cannot be read: ${(err as Error).message}` });
      },
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
  // Kept for whatever request the parser read, since only this request's
  // own routes ever look at it. Nothing extra is read: the parser has
  // already read these bytes.
  (req as WithRawBody)[RAW_BODY] = buf;
}

/** What the callback says when the text it needs is gone. */
const RAW_BODY_GONE =
  "a body parser read the assertion before this route could see its text; mount " +
  "identityAgentCallbackBody() before your body parsers (with { path } naming the " +
  "callback's full path if the routes sit under a prefix), or give them " +
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
        if (err instanceof BodyTooLarge) res.setHeader("Connection", "close");
        return res.status(unreadableStatus(err)).json({ error: `the request cannot be read: ${(err as Error).message}` });
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
        if (err instanceof BodyTooLarge) res.setHeader("Connection", "close");
        return res.status(unreadableStatus(err)).json({ error: `the assertion cannot be read: ${(err as Error).message}` });
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