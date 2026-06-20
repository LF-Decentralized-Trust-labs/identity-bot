import * as ed from "@noble/ed25519";
import { CLAIM_NAMESPACE } from "./profile.js";
import type { IDTokenVerifyResult } from "./types.js";
import type { LoginAssertion } from "../types.js";
import { resolveFromDidWebs } from "../resolver.js";

const CLAIM_SEAM8_ASSERTION = `${CLAIM_NAMESPACE}/seam8_assertion`;

/** Parse a JWT without validation (utility). */
export function parseJWT(token: string): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid JWT");
  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  return { header, payload };
}

/** Verify EdDSA JWT signature using did:webs-resolved key. */
export async function verifyIDTokenSignature(
  token: string,
  fetchFn: typeof fetch = fetch,
): Promise<{ ok: boolean; reason?: string; publicKey?: Uint8Array }> {
  const jwtParts = token.split(".");
  if (jwtParts.length !== 3) return { ok: false, reason: "invalid JWT" };
  const { header, payload } = parseJWT(token);
  const kid = header.kid as string | undefined;
  const iss = payload.iss as string | undefined;
  if (!kid || !iss?.startsWith("did:webs:")) {
    return { ok: false, reason: "missing kid or did:webs iss" };
  }
  const rest = iss.slice("did:webs:".length);
  const didParts = rest.split(":");
  const aid = didParts[didParts.length - 1]!;
  const host = didParts.slice(0, -1).join(":");
  const relayBase = host.includes("/")
    ? `http://${host.replace(/:/g, "/")}`
    : `http://${host}`;
  let publicKey: Uint8Array;
  try {
    const resolved = await resolveFromDidWebs(`${relayBase}/oobi/${aid}`, aid, fetchFn);
    publicKey = resolved.publicKey;
  } catch (err) {
    return { ok: false, reason: `key resolve failed: ${(err as Error).message}` };
  }
  const signed = `${jwtParts[0]}.${jwtParts[1]}`;
  const sig = Buffer.from(jwtParts[2], "base64url");
  const valid = await ed.verifyAsync(sig, new TextEncoder().encode(signed), publicKey);
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
  maxSkewSeconds?: number;
  fetchFn?: typeof fetch;
}

/**
 * Verify OIDC ID token: JWT sig via did:webs, then delegate login checks to verifyAssertion.
 */
export async function verifyIDToken(
  token: string,
  opts: VerifyIDTokenOptions,
  verifyAssertion: (
    assertion: LoginAssertion,
    vopts: { expectedAudience: string; expectedNonce: string; maxSkewSeconds?: number },
  ) => Promise<{ ok: boolean; reason?: string }>,
): Promise<IDTokenVerifyResult> {
  const sig = await verifyIDTokenSignature(token, opts.fetchFn);
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
    maxSkewSeconds: opts.maxSkewSeconds,
  });
  if (!substrate.ok) return { ok: false, reason: `login: ${substrate.reason}` };

  return {
    ok: true,
    iss: payload.iss as string,
    sub: payload.sub as string,
    nonce: payload.nonce as string,
    audience: payload.aud as string,
    disclosures: disclosuresFromIDToken(payload),
    assertion,
  };
}