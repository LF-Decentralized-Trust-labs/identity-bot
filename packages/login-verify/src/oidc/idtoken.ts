import { CLAIM_NAMESPACE } from "./profile.js";
import type { IDTokenVerifyResult } from "./types.js";
import type { LoginAssertion } from "../types.js";
import { NO_KEY_RESOLVER, type KeyResolver } from "../resolver.js";
import { decodeBase64UrlStrict, verifyEd25519 } from "../canonical.js";

const CLAIM_SEAM8_ASSERTION = `${CLAIM_NAMESPACE}/seam8_assertion`;

/** Parse a JWT without validation (utility). */
export function parseJWT(token: string): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid JWT");
  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  return { header, payload };
}

/** Verify the EdDSA JWT signature with the issuer's key, established from the
 *  key log the embedded login assertion carries. */
export async function verifyIDTokenSignature(
  token: string,
  resolveKey?: KeyResolver,
): Promise<{ ok: boolean; reason?: string; publicKey?: Uint8Array }> {
  const jwtParts = token.split(".");
  if (jwtParts.length !== 3) return { ok: false, reason: "invalid JWT" };
  const { header, payload } = parseJWT(token);
  const kid = header.kid as string | undefined;
  const iss = payload.iss as string | undefined;
  if (!kid || !iss?.startsWith("did:webs:")) {
    return { ok: false, reason: "missing kid or did:webs iss" };
  }
  const didParts = iss.slice("did:webs:".length).split(":");
  const aid = didParts[didParts.length - 1]!;
  if (!resolveKey) return { ok: false, reason: NO_KEY_RESOLVER };
  let publicKey: Uint8Array;
  try {
    publicKey = await resolveKey(aid, assertionFromIDToken(payload)?.p_kel);
  } catch (err) {
    return { ok: false, reason: `key resolve failed: ${(err as Error).message}` };
  }
  const signed = `${jwtParts[0]}.${jwtParts[1]}`;
  const sig = decodeBase64UrlStrict(jwtParts[2], 64);
  if (!sig) return { ok: false, reason: "invalid JWT signature" };
  const valid = await verifyEd25519(sig, new TextEncoder().encode(signed), publicKey);
  if (!valid) return { ok: false, reason: "invalid JWT signature" };
  return { ok: true, publicKey };
}

/** Extract the login assertion embedded in JWT for verifyAssertion substrate check. */
export function assertionFromIDToken(payload: Record<string, unknown>): LoginAssertion | null {
  const embedded = payload[CLAIM_SEAM8_ASSERTION];
  if (!embedded || typeof embedded !== "object") return null;
  return embedded as LoginAssertion;
}

/** Map OIDC claims back to login disclosures. */
export function disclosuresFromIDToken(payload: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  if (typeof payload.name === "string") out.display_name = payload.name;
  if (typeof payload.email === "string") out.email = payload.email;
  for (const [k, v] of Object.entries(payload)) {
    if (k.startsWith(`${CLAIM_NAMESPACE}/`) && typeof v === "string") {
      out[k.slice(`${CLAIM_NAMESPACE}/`.length)] = v;
    }
  }
  return out;
}

export interface VerifyIDTokenOptions {
  expectedAudience: string;
  expectedNonce: string;
  /** This site's own identifier: the embedded assertion must name it. */
  expectedSiteAid: string;
  maxSkewSeconds?: number;
  /** Establishes the issuer's key from the embedded assertion's key log.
   *  Without one every token is refused; see `keyFromIdentityAgent`. */
  resolveKey?: KeyResolver;
}

/**
 * Verify OIDC ID token: JWT sig by the key the issuer's own key log holds, then
 * delegate login checks to verifyAssertion.
 */
export async function verifyIDToken(
  token: string,
  opts: VerifyIDTokenOptions,
  verifyAssertion: (
    assertion: LoginAssertion,
    vopts: { expectedAudience: string; expectedNonce: string; expectedSiteAid: string; maxSkewSeconds?: number },
  ) => Promise<{ valid: boolean; reason?: string }>,
  // Optional policy check — whether this person is allowed in, which is a
  // different question from whether they are who they say. Omitting it admits
  // anybody who verifies, which is right for an open site; the result reports
  // that no policy was applied so the omission is not silent.
  authorize?: (
    assertion: LoginAssertion,
  ) => Promise<{ allowed: boolean; reason?: string }>,
): Promise<IDTokenVerifyResult> {
  const sig = await verifyIDTokenSignature(token, opts.resolveKey);
  if (!sig.ok) return { ok: false, reason: sig.reason };

  const { payload } = parseJWT(token);
  if (payload.aud !== opts.expectedAudience) {
    return { ok: false, reason: "audience mismatch" };
  }
  if (payload.nonce !== opts.expectedNonce) {
    return { ok: false, reason: "nonce mismatch" };
  }
  const now = Math.floor(Date.now() / 1000);
  const exp = payload.exp as number | undefined;
  const iat = payload.iat as number | undefined;
  const skew = opts.maxSkewSeconds ?? 300;
  if (exp && now > exp + skew) return { ok: false, reason: "token expired" };
  if (iat && now < iat - skew) return { ok: false, reason: "token not yet valid" };

  const assertion = assertionFromIDToken(payload);
  if (!assertion) return { ok: false, reason: "missing embedded seam8_assertion" };

  const substrate = await verifyAssertion(assertion, {
    expectedAudience: opts.expectedAudience,
    expectedNonce: opts.expectedNonce,
    expectedSiteAid: opts.expectedSiteAid,
    maxSkewSeconds: opts.maxSkewSeconds,
  });
  if (!substrate.valid) return { ok: false, reason: `login: ${substrate.reason}` };

  if (authorize) {
    const decision = await authorize(assertion);
    if (!decision.allowed) {
      // Uniform outward, for the same reason the native path is uniform: a
      // specific reason here is an oracle anybody can query.
      return { ok: false, reason: "not authorized", authorized: false };
    }
  }

  return {
    ok: true,
    authorized: authorize ? true : undefined,
    iss: payload.iss as string,
    sub: payload.sub as string,
    nonce: payload.nonce as string,
    audience: payload.aud as string,
    disclosures: disclosuresFromIDToken(payload),
    assertion,
  };
}