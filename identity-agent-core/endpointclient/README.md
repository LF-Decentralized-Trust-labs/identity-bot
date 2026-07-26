# endpointclient — Identity Agent capability-endpoint client

A client for the Identity Agent's governed capability endpoint. It handles the
bearer token and, optionally, **signed-request envelopes** — signing each call so
the endpoint can prove the caller signed *this* request, on top of the token.

## Flow

```go
// 1. The Identity Agent (or an operator) provisions an agent — a local-owner call.
p, _ := endpointclient.ProvisionAgent(ctx, "http://127.0.0.1:5050",
    "acme-support-agent", []string{"infra.zone.list"}, nil, nil)

// 2. The agent invokes capabilities with the returned token.
c := endpointclient.New("http://127.0.0.1:5050", p.Token)
res, _ := c.Invoke(ctx, "infra.zone.list", nil)

// 3. Optionally attach a signed envelope (per-request signature).
signer, _ := endpointclient.NewLocalKeySigner(agentSeed, p.AgentAID)
c = endpointclient.New(baseURL, p.Token, endpointclient.WithSigner(signer))
res, _ = c.Invoke(ctx, "infra.zone.list", nil)
```

`Signer` is an interface: sign with a local key (`LocalKeySigner`) or delegate to
the Identity Agent to sign on the agent's behalf (the IA-mediated model, where the
agent never holds standalone signing authority). Whoever signs, the endpoint must
be able to resolve the signer AID's public key.

## The signed-request envelope contract

The envelope travels in **HTTP headers**, so the JSON-RPC body is byte-identical to
a plain call:

| Header | Value |
|---|---|
| `X-IA-Signature` | detached Ed25519 signature, CESR `0B` qb64, over the canonical payload |
| `X-IA-Nonce` | unique per request (anti-replay) |
| `X-IA-Timestamp` | unix seconds (must be within the endpoint's freshness window, ~5 min) |
| `X-IA-Signer-AID` | the signer's AID (optional; defaults to the authenticated caller) |

**Canonical payload** (the exact bytes signed) — must match the endpoint byte-for-byte:

```
method + "\n" + hex(sha256(params)) + "\n" + nonce + "\n" + timestamp
```

where `method` is the JSON-RPC method (`"tools/call"`) and `params` is the exact
bytes of the JSON-RPC `params` field. Marshal `params` once and reuse the same bytes
for both the body and the signature.

## TypeScript reference

For non-Go agents. Untested reference — the canonical-payload format above is the
contract; verify against a live endpoint before relying on it.

```ts
import { createHash, randomBytes, sign } from "node:crypto";

// CESR "0B" encode: 1 pad byte (0x00) prepended, base64url, drop the first char.
function cesr0B(sig: Uint8Array): string {
  const padded = new Uint8Array(1 + sig.length); // leading 0x00
  padded.set(sig, 1);
  return "0B" + Buffer.from(padded).toString("base64url").slice(1);
}

function canonicalPayload(method: string, params: string, nonce: string, ts: string): string {
  const h = createHash("sha256").update(params).digest("hex");
  return `${method}\n${h}\n${nonce}\n${ts}`;
}

export async function invokeSigned(baseURL: string, token: string,
    ed25519PrivateKeyPem: string, signerAID: string,
    capabilityId: string, args: Record<string, unknown> = {}) {
  const params = JSON.stringify({ name: "execute", arguments: { capability_id: capabilityId, args } });
  const body   = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: JSON.parse(params) });
  const nonce  = randomBytes(16).toString("hex");
  const ts     = Math.floor(Date.now() / 1000).toString();
  const sig    = sign(null, Buffer.from(canonicalPayload("tools/call", params, nonce, ts)),
                      ed25519PrivateKeyPem);
  const res = await fetch(`${baseURL}/api/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`,
      "X-IA-Signature": cesr0B(sig),
      "X-IA-Nonce": nonce,
      "X-IA-Timestamp": ts,
      "X-IA-Signer-AID": signerAID,
    },
    body,
  });
  return res.json();
}
```

> Note: `params` in `canonicalPayload` must be the exact string embedded in the
> body's `params` field. The example re-parses it into the body via `JSON.parse` so
> the bytes hashed and the bytes sent are the same logical value; if your JSON
> serializer reorders keys, serialize `params` once and inject it verbatim.
