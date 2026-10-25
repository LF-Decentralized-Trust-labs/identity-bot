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

/**
 * Establishes an identity's current signing key from its key log.
 *
 * `keyLog` is the signed key log a login assertion carries (`p_kel`). A key is
 * tied to an identifier only by a log whose inception derives that identifier
 * and whose events are signed by the keys they declare; a key read from a
 * did.json at an address the assertion names is not, because whoever wrote the
 * assertion also chose the address. A resolver must refuse (throw) when the log
 * does not establish a key for `aid`.
 */
export type KeyResolver = (aid: string, keyLog: string | undefined) => Promise<Uint8Array>;

/**
 * The reason a verifier with no way to check a key log refuses, rather than
 * falling back to reading a key from wherever an assertion says it lives.
 */
export const NO_KEY_RESOLVER =
  "no way to check this identity's key log: give the verifier a resolveKey, such as " +
  "keyFromIdentityAgent(<an Identity Agent you trust>)";

/**
 * A resolver that asks an Identity Agent to check the key log.
 *
 * Checking a key log means re-deriving an identifier from the exact bytes of
 * its inception and verifying every event's signature. That check already
 * exists, once, in the Identity Agent; this asks it (`POST /public/login/key`)
 * instead of keeping a second implementation here that could drift from it on
 * the one question that decides whether a stranger is who they claim. The
 * Identity Agent fetches nothing and stores nothing to answer.
 */
export function keyFromIdentityAgent(
  identityAgentUrl: string,
  fetchFn: typeof fetch = fetch,
): KeyResolver {
  // The answer is a key this verifier will trust, so it is fetched over TLS:
  // over plain HTTP anybody on the path could answer with a key of their own.
  // Only an Identity Agent on this same machine is reached without it.
  const parsed = new URL(identityAgentUrl);
  const local = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(parsed.hostname);
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && local)) {
    throw new Error(
      `${identityAgentUrl} is not an https address; an Identity Agent is asked for keys over TLS ` +
        "unless it is on this machine",
    );
  }
  const url = `${identityAgentUrl.replace(/\/$/, "")}/public/login/key`;
  return async (aid, keyLog) => {
    if (!keyLog) {
      throw new Error(`no key log came with this, so nothing ties a key to ${aid}`);
    }
    const resp = await fetchFn(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ aid, key_log: keyLog }),
    });
    const out = (await resp.json().catch(() => ({}))) as { public_key_b64?: string; error?: string };
    if (!resp.ok || !out.public_key_b64) {
      throw new Error(out.error ?? `the Identity Agent at ${identityAgentUrl} answered ${resp.status}`);
    }
    return new Uint8Array(Buffer.from(out.public_key_b64, "base64url"));
  };
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
