import * as ed from "@noble/ed25519";
import {
  assertionDigest,
  canonicalAssertionBody,
  canonicalChallengeBody,
  nonTransferableAidQb64,
  randomToken,
  rfc3339Utc,
  signCanonical,
} from "./canonical.js";
import type { KeyResolver } from "./resolver.js";
import { verifyLoginAssertion } from "./standalone-verify.js";
import { InMemorySessionStore } from "./session-store.js";
import { buildLoginQrUrl } from "./qr-url.js";
import { AskAction } from "./types.js";
import type {
  CreateChallengeOptions,
  LoginAssertion,
  LoginChallenge,
  SessionState,
  SiteIdentity,
  VerifyAssertionOptions,
  VerifyAssertionResult,
} from "./types.js";

export interface VerifierConfig {
  siteIdentity: SiteIdentity;
  sessionStore?: InMemorySessionStore;
  challengeTtlSeconds?: number;
  devRelayBaseUrl?: string;
  /** Establishes an asserter's key from the key log its assertion carries.
   *  Without one every assertion is refused; see `keyFromIdentityAgent`. */
  resolveKey?: KeyResolver;
}

/** The states in which a sign-in is still waiting for its answer. */
const CALLBACK_STATES = new Set<SessionState>(["created", "scanned", "connected"]);

export class IdentityAgentVerifier {
  private site: SiteIdentity;
  private store: InMemorySessionStore;
  private challengeTtl: number;
  private devRelayBaseUrl?: string;
  private resolveKey?: KeyResolver;

  constructor(config: VerifierConfig) {
    this.site = config.siteIdentity;
    this.store = config.sessionStore ?? new InMemorySessionStore();
    this.challengeTtl = config.challengeTtlSeconds ?? 300;
    this.devRelayBaseUrl = config.devRelayBaseUrl;
    this.resolveKey = config.resolveKey;
  }

  get sessionStore(): InMemorySessionStore {
    return this.store;
  }

  async createChallenge(opts: CreateChallengeOptions): Promise<{
    bundle: LoginChallenge;
    session_token: string;
    relay_or_qr_url: string;
    qr_url: string;
    expires_at: string;
  }> {
    const sessionToken = opts.sessionToken ?? randomToken(16);
    const nonce = randomToken();
    const dt = rfc3339Utc(0);
    const expiresAt = rfc3339Utc(this.challengeTtl);

    const challenge: LoginChallenge = {
      v: "ASK1",
      t: AskAction.login,
      site_aid: this.site.aid,
      site_oobi: this.site.oobiUrl,
      audience: opts.audience,
      nonce,
      dt,
      expiry: expiresAt,
      requested_disclosures: opts.requestedDisclosures,
      requested_credentials: opts.requestedCredentials ?? [],
      callback_url: opts.callbackUrl,
      session_token: sessionToken,
    };
    if (opts.requestScore) {
      challenge.requested_score = opts.requestScore;
    }

    const body = canonicalChallengeBody(challenge);
    challenge.sig = await signCanonical(body, this.site.privateKey);

    // Copy-link / manual-entry fallback keeps the full OOBI form. The QR itself
    // is the minimal bundle pointer on the RP origin (== audience).
    const relayOrQrUrl = `${this.site.oobiUrl}?action=login&session=${sessionToken}`;
    const qrUrl = buildLoginQrUrl(opts.audience, sessionToken);

    this.store.set({
      token: sessionToken,
      state: "created",
      challenge,
      relayOrQrUrl,
      expiresAt,
    });

    return {
      bundle: challenge,
      session_token: sessionToken,
      relay_or_qr_url: relayOrQrUrl,
      qr_url: qrUrl,
      expires_at: expiresAt,
    };
  }

  getSessionState(token: string): { state: string; appSessionToken?: string } | null {
    const rec = this.store.get(token);
    if (!rec) return null;
    return {
      state: rec.state,
      appSessionToken: rec.appSessionToken,
    };
  }

  async verifyAssertion(
    assertion: LoginAssertion,
    opts: VerifyAssertionOptions,
  ): Promise<VerifyAssertionResult> {
    // Only what this method promises to take: anything else on the caller's
    // object (a key of its own, a clock, a flag to skip the time check) is
    // not passed on to the verifier.
    return verifyLoginAssertion(assertion, {
      expectedAudience: opts.expectedAudience,
      expectedNonce: opts.expectedNonce,
      expectedSiteAid: opts.expectedSiteAid,
      maxSkewSeconds: opts.maxSkewSeconds,
      resolveKey: this.resolveKey,
    });
  }

  async handleCallback(
    assertion: LoginAssertion,
    sessionToken: string,
    issueAppSession: (pairwiseAid: string, disclosures: Record<string, string>) => string,
  ): Promise<{ ok: boolean; reason?: string }> {
    const rec = this.store.get(sessionToken);
    if (!rec) {
      return { ok: false, reason: "unknown session" };
    }
    // Only a sign-in still waiting for its answer can be answered. An expired
    // or declined one stays that way, and a verified one is not verified
    // again by whatever is posted next.
    if (!CALLBACK_STATES.has(rec.state)) {
      return { ok: false, reason: `this sign-in is ${rec.state}, so it cannot be answered` };
    }

    const result = await this.verifyAssertion(assertion, {
      expectedAudience: rec.challenge.audience,
      expectedNonce: rec.challenge.nonce,
      expectedSiteAid: rec.challenge.site_aid,
    });
    if (!result.valid || !result.pairwiseAID) {
      return { ok: false, reason: result.reason };
    }

    const appToken = issueAppSession(result.pairwiseAID, result.disclosures ?? {});
    this.store.markVerified(sessionToken, result, result.pairwiseAID, appToken);
    return { ok: true };
  }
}

/**
 * Generate a development site identity: an Ed25519 keypair named by a
 * non-transferable identifier (code B), which is the key itself.
 *
 * Development only. The identifier is real and anyone can check a signature
 * under it, but it has no key log and can never rotate, and an Identity Agent
 * checks a site's key log, so it refuses every challenge this signs. A real site
 * signs in people through its organisation's Identity Agent: its sign-in
 * identity is an asset of that agent, which serves the site's key log and
 * checks people's key logs (`keyFromIdentityAgent`).
 */
export async function generateDevSiteIdentity(relayBaseUrl: string): Promise<SiteIdentity> {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  const aid = nonTransferableAidQb64(publicKey);
  const oobiUrl = `${relayBaseUrl}/oobi/${aid}`;
  return { aid, publicKey, privateKey, oobiUrl };
}

export { assertionDigest, canonicalAssertionBody, canonicalChallengeBody };