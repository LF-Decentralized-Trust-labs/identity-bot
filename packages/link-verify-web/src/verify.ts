import type {
  Flow,
  Tier,
  VerificationResult,
  VerifyOptions,
  VerifyRequest,
} from "./types.js";

const DEFAULT_CORE = "http://127.0.0.1:5050";

/**
 * verify() — link verification entry for browser embedders.
 *
 * Calls the IA loopback route GET /api/verification/badge.
 * Third-party embedders without a local IA receive unverified from fetch failures.
 * In-process Go SDK is preferred when available; this package is for web surfaces.
 */
export async function verify(
  input: string,
  options: VerifyOptions = {}
): Promise<VerificationResult> {
  const base = (options.coreBaseUrl ?? DEFAULT_CORE).replace(/\/$/, "");
  const flow: Flow = options.flow ?? "link";
  const tier: Tier = options.tier ?? "free";
  const params = new URLSearchParams({
    url: input,
    flow,
    tier,
  });
  if (options.forceRefresh) {
    params.set("refresh", "1");
  }

  const url = `${base}/api/verification/badge?${params.toString()}`;
  try {
    const res = await fetch(url, { method: "GET", credentials: "omit" });
    if (!res.ok) {
      return neutralResult(input);
    }
    const body = (await res.json()) as VerificationResult;
    return body;
  } catch {
    return neutralResult(input);
  }
}

/** Typed request/response for non-browser callers. */
export async function verifyRequest(
  req: VerifyRequest,
  coreBaseUrl = DEFAULT_CORE
): Promise<VerificationResult> {
  return verify(req.input, {
    coreBaseUrl,
    flow: req.flow,
    tier: req.tier,
    timing: req.timing,
    forceRefresh: req.force_refresh,
  });
}

function neutralResult(_input: string): VerificationResult {
  return {
    outcome: "unverified",
    aid: null,
    verification_path: "none",
    last_verified: new Date().toISOString(),
    contact_correlation: null,
    band: "gray",
    band_style: "generic",
  };
}