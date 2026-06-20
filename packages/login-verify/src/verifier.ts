import * as ed from "@noble/ed25519";
import {
  assertionDigest,
  canonicalAssertionBody,
  canonicalChallengeBody,
  parseRfc3339,
  randomToken,
  rfc3339Utc,
  signCanonical,
  verifyCanonical,
} from "./canonical.js";
import { resolveFromDidWebs } from "./resolver.js";
import { InMemorySessionStore } from "./session-store.js";
import { buildLoginQrUrl } from "./qr-url.js";
import { AskAction } from "./types.js";
import type {
  CreateChallengeOptions,
  LoginAssertion,
  LoginChallenge,
  SiteIdentity,
  VerifyAssertionOptions,
  VerifyAssertionResult,
} from "./types.js";

export interface VerifierConfig {
  siteIdentity: SiteIdentity;
  sessionStore?: InMemorySessionStore;
  challengeTtlSeconds?: number;
  devRelayBaseUrl?: string;
}

export class IdentityAgentVerifier {
  private site: SiteIdentity;
  private store: InMemorySessionStore;
  private challengeTtl: number;
  private devRelayBaseUrl?: string;

  constructor(config: VerifierConfig) {
    this.site = config.siteIdentity;
    this.store = config.sessionStore ?? new InMemorySessionStore();
    this.challengeTtl = config.challengeTtlSeconds ?? 300;
    this.devRelayBaseUrl = config.devRelayBaseUrl;
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
    const maxSkew = opts.maxSkewSeconds ?? 300;
    const now = Date.now();
    const dtMs = parseRfc3339(assertion.dt);
    if (Math.abs(now - dtMs) > maxSkew * 1000) {
      return { ok: false, reason: "dt outside freshness window" };
    }
    if (assertion.nonce !== opts.expectedNonce) {
      return { ok: false, reason: "nonce mismatch" };
    }
    if (assertion.audience !== opts.expectedAudience) {
      return { ok: false, reason: "audience mismatch" };
    }
    if (!assertion.sig) {
      return { ok: false, reason: "missing sig" };
    }

    let publicKey: Uint8Array;
    try {
      const resolved = await resolveFromDidWebs(
        assertion.relationship_aid_oobi,
        assertion.i,
      );
      publicKey = resolved.publicKey;
    } catch (err) {
      return { ok: false, reason: `key resolve failed: ${(err as Error).message}` };
    }

    const body = canonicalAssertionBody(assertion);
    const valid = await verifyCanonical(body, assertion.sig, publicKey);
    if (!valid) {
      return { ok: false, reason: "invalid signature" };
    }

    return {
      ok: true,
      i: assertion.i,
      disclosures: assertion.disclosures,
      presentedAcdcs: assertion.presented_acdcs,
      customData: assertion.custom_data,
      nonce: assertion.nonce,
      audience: assertion.audience,
      dt: assertion.dt,
    };
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
    if (rec.state === "verified") {
      return { ok: true };
    }

    const result = await this.verifyAssertion(assertion, {
      expectedAudience: rec.challenge.audience,
      expectedNonce: rec.challenge.nonce,
    });
    if (!result.ok || !result.i) {
      return { ok: false, reason: result.reason };
    }

    const appToken = issueAppSession(result.i, result.disclosures ?? {});
    this.store.markVerified(sessionToken, result, result.i, appToken);
    return { ok: true };
  }
}

/** Generate a dev site identity (Ed25519 keypair + synthetic AID prefix). */
export async function generateDevSiteIdentity(relayBaseUrl: string): Promise<SiteIdentity> {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  const aid = `E${Buffer.from(publicKey).toString("base64url").slice(0, 43)}`;
  const oobiUrl = `${relayBaseUrl}/oobi/${aid}`;
  return { aid, publicKey, privateKey, oobiUrl };
}

export { assertionDigest, canonicalAssertionBody, canonicalChallengeBody };