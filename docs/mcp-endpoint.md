# The Identity Agent's MCP Endpoint

The Identity Agent exposes its governed capabilities to AI agents and tools through
one endpoint speaking the Model Context Protocol (MCP):

```
POST <agent base URL>/api/mcp
```

Locally that is `http://127.0.0.1:5050/api/mcp` (desktop) or
`http://127.0.0.1:8642/api/mcp` (mobile embedded core). When the agent has an
active tunnel, the same endpoint is reachable at
`https://<your-tunnel-host>/api/mcp` — the public URL is shown by
`GET /api/endpoint`.

The transport is standard JSON-RPC 2.0 over HTTP POST, implementing `initialize`,
`ping`, `tools/list`, and `tools/call` — any MCP-capable client can connect. For
example, Claude Code:

```sh
claude mcp add --scope user --transport http my-agent \
  https://<your-tunnel-host>/api/mcp \
  --header "Authorization: Bearer <token>"
```

## The three meta-tools

Rather than one MCP tool per capability (which would grow a caller's context
without bound), the endpoint exposes three meta-tools whose cost to a caller is
constant regardless of catalog size:

| Tool | Input | Returns |
|---|---|---|
| `search` | `{query?, domain?, executor_type?, limit?}` | Ranked capability summaries (id, name, description — never schemas), filtered to what the caller is entitled to invoke |
| `describe` | `{capability_id}` | One capability's full record: input schema, credential requirements, and a ready-to-use `execute` call |
| `execute` | `{capability_id, args}` | The result, wrapped as `{capability_id, status, correlation_id, audit_event_id, body}` |

While the catalog is small, capabilities are also projected as flat tools in
`tools/list` for zero-shot client compatibility.

## Authentication

Callers present a bearer token:

```
Authorization: Bearer <token>
```

Tokens are minted by the agent's owner (local-owner only: `POST /api/mcp/tokens`
with `{name, scopes}`, where scopes are capability ids), listed with `GET`, and
revoked with `DELETE /api/mcp/tokens/{name}`. A token's plaintext is returned
exactly once at minting; the agent stores only a hash.

Requests from the agent's own loopback interface (with no proxy-forwarding
headers) are treated as the local owner. Everything else is a remote caller and
must present a valid token; a remote caller without one — or outside its scopes —
is denied by default.

## Governance: what every caller gets, and never gets

Every `execute` passes one governed chokepoint:

1. **Who is calling** — the caller is resolved from its positive credential,
   never from connection origin.
2. **May they** — default-deny authorization against the caller's scopes; some
   capability classes (`host_control` — machine-level capabilities such as
   computer use) are never remote-invocable regardless of credentials.
3. **Egress** — provider credentials (API keys) live only in the agent's
   encrypted vault and are injected into the outbound request after
   authorization. **A caller never sees a credential**, in any response, ever.
4. **The record** — every invocation (including denials) writes one
   cryptographically signed audit event: caller, capability, argument hash,
   status, timing, and a `correlation_id` propagated across hops. The
   `audit_event_id` in each `execute` response cites that record.

Management surfaces — storing credentials, minting tokens, importing capability
packs — are local-owner only and are never served to remote callers, tunneled or
not.

## Quick reference

| What | Where |
|---|---|
| MCP endpoint | `POST /api/mcp` |
| Public URL of this agent | `GET /api/endpoint` |
| Capability catalog (owner view) | `GET /api/capability-registry` |
| Tokens (owner only) | `POST/GET /api/mcp/tokens`, `DELETE /api/mcp/tokens/{name}` |
| Signed invocation log (owner view) | `GET /api/activity/invocations` |
| One invocation, with its authority line resolved | `GET /api/activity/invocations/{id}` |
| Activity totals — counts by status and executor, cost grouped by unit | `GET /api/activity/summary` |
| Verify the log has not been tampered with | `GET /api/activity/chain` |
| The forward proxy's certificate authority, for a caller that must trust it | `GET /api/proxy/ca.crt` |
