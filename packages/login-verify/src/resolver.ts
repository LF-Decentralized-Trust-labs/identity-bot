import { ed25519VerkeyQb64 } from "./canonical.js";

export interface DidWebsDocument {
  id: string;
  verificationMethod: Array<{
    id: string;
    type: string;
    controller: string;
    publicKeyMultibase?: string;
    publicKeyJwk?: { crv: string; x: string; kty: string };
  }>;
}

export interface ResolvedKey {
  aid: string;
  publicKey: Uint8Array;
  verkeyQb64: string;
}

/** Path 2: resolve signing key from did:webs document at relay URL. */
export async function resolveFromDidWebs(
  relayOobiUrl: string,
  aid: string,
  fetchFn: typeof fetch = fetch,
): Promise<ResolvedKey> {
  const base = relayOobiUrl.replace(/\/oobi\/.*$/, "").replace(/\/$/, "");
  const didUrl = `${base}/${aid}/did.json`;
  const resp = await fetchFn(didUrl);
  if (!resp.ok) {
    throw new Error(`did:webs resolve failed: ${resp.status} ${didUrl}`);
  }
  const doc = (await resp.json()) as DidWebsDocument;
  const vm = doc.verificationMethod?.[0];
  if (!vm?.publicKeyJwk?.x) {
    throw new Error("did.json missing Ed25519 publicKeyJwk");
  }
  const pub = Buffer.from(vm.publicKeyJwk.x, "base64url");
  return { aid, publicKey: pub, verkeyQb64: ed25519VerkeyQb64(pub) };
}

/** Build a minimal did:webs document for dev relay stub. */
export function buildDidWebsDocument(aid: string, relayHost: string, publicKey: Uint8Array): DidWebsDocument {
  const vmId = `did:webs:${relayHost}:${aid}#key-1`;
  return {
    id: `did:webs:${relayHost}:${aid}`,
    verificationMethod: [
      {
        id: vmId,
        type: "Ed25519VerificationKey2020",
        controller: `did:webs:${relayHost}:${aid}`,
        publicKeyJwk: {
          kty: "OKP",
          crv: "Ed25519",
          x: Buffer.from(publicKey).toString("base64url"),
        },
      },
    ],
  };
}