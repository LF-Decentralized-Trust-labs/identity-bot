import type { OIDCDiscoveryDocument } from "./types.js";

/** Fetch and parse openid-configuration from a pairwise issuer base. */
export async function fetchDiscovery(
  issuerBase: string,
  fetchFn: typeof fetch = fetch,
): Promise<OIDCDiscoveryDocument> {
  const url = `${issuerBase.replace(/\/$/, "")}/.well-known/openid-configuration`;
  const resp = await fetchFn(url);
  if (!resp.ok) {
    throw new Error(`discovery fetch failed: ${resp.status} ${url}`);
  }
  return (await resp.json()) as OIDCDiscoveryDocument;
}