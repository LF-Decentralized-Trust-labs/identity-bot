# ADR-057 — An API key stays with the Identity Agent, which makes each model call

**Status:** Accepted
**Date:** 2026-10-28
**Amended:** 2026-10-30 — trimmed to the exchange a machine follows. How an Identity Agent that holds AI agents keeps the key, routes the call, caps a machine's calls and records what each call cost is that runtime's own decision, kept with it outside this repository. Also 2026-10-30 — the exchange a machine sees when the Identity Agent holds the AI agent's model calls to an allowance. Also 2026-10-30 — the exchange stated as the published checks (package `modelcall`) enforce it, with each provider's routes, headers, query parameters and answer-length fields listed by the Identity Agent rather than fixed here.
**Relates to:** ADR-046 (A machine becomes an AI agent's body by a person comparing six words), ADR-047 (AI agents talk through the Identity Agent that holds them), ADR-056 (Revoking an AI agent is final)

## Context

An AI agent's body runs a program, its brain, that calls a model provider. If
the body were lent the provider's API key, a compromised body could copy it,
and the key would work anywhere until replaced. So the key stays with the
Identity Agent, and the body's brain makes each model call through it.

A machine from any provider must be able to act as a body, so the exchange it
follows is published here.

## Decision

**The brain is pointed at the body.** The body gives its brain an address on
its own loopback server and a token made for that run. The brain sends its
provider calls there. The body passes each one on to the Identity Agent, and
the Identity Agent adds the key.

**Every request below is sealed and signed** by the body, as everything it
sends the Identity Agent is (ADR-047).

The exchange is published as
`identity-agent-core/contracts/model-call/model-call.schema.json`, with worked
examples in `identity-agent-core/modelcall/model-call-vectors.json`.

### Borrowing the sign-in: `POST /api/agent-host/brain-sign-in`

A run starts by borrowing its AI agent's sign-in. A body that makes its
brain's model calls through the Identity Agent says so:
`{"model_calls": "through_identity_agent"}`. The answer carries the run's
`lease_id`, `lease_expires_at`, `renew_every_seconds` and the same
`model_calls`, and no key. The body keeps the lease with
`POST /api/agent-host/brain-sign-in/renew` and gives it back with
`POST /api/agent-host/brain-sign-in/return`, each sending
`{"lease_id": "…"}`. A renewal keeps the same `lease_id` and answers with a new
`lease_expires_at`. A lease not renewed by its `lease_expires_at` lapses: from
then on, a renewal or return naming it is answered 404 with `"no_lease": true`,
and a model call naming it is refused 403. A call already under way goes on
while the same machine holds another open lease on the sign-in, and is
otherwise stopped, its answer ending with an error. A body whose lease lapsed
borrows again and names the new lease in its next collection. A body that does
not say it makes its calls through the Identity Agent is refused 409 with
`"update_agent_host": true`, and is never lent the key.

### Starting a call: `POST /api/agent-host/model-calls`

```json
{
  "lease_id": "the run's lease on the AI agent's sign-in",
  "method":   "POST",
  "path":     "/v1/generate",
  "query":    "preview=true",
  "header":   {"Content-Type": "application/json"},
  "body_b64": "the brain's request body, base64"
}
```

The schema states each rule exactly. In short:

- **The provider's profile.** For each provider, the Identity Agent lists the
  routes a call may take, the headers that travel on and back, the query
  parameters a call may carry, and the fields by which a model call says how
  long an answer it wants and how many answers. The routes are the provider's
  model calls, its list of models, one model by name below that list, and its
  own read-only and counting routes, such as counting a request's tokens or
  reading the key's own details. The checks read that profile. Nothing outside
  it is made. A profile that is not valid (a lower-case route method, a header
  name that is not an HTTP header name, a name listed twice ignoring ASCII
  case, or a query parameter with other than one rule) allows no call.
- **The method** is GET or POST, in any ASCII case, whatever the profile lists.
- **The path** must be plain: at most 256 bytes, starting with `/`, holding
  only ASCII letters, digits and `. - _ : / ~`, and unchanged by cleaning.
- **The query** carries only the profile's parameters, each at most once, on
  any route. A paging value may be empty. The query is sent on re-encoded,
  sorted by name.
- **Headers** are the profile's, matched in any ASCII case. Any other header is
  dropped, not refused. Whatever a profile lists, credentials and
  per-connection headers never travel, on or back: `Authorization`,
  `Authentication`, `Proxy-Authorization`, `Cookie`, `Cookie2`, `Set-Cookie`,
  `Set-Cookie2`, `X-Api-Key`, `Api-Key`, `X-Auth-Token`, `Host`,
  `Content-Length`, `Transfer-Encoding`, `Connection`, `Keep-Alive`,
  `Proxy-Connection`, `TE`, `Trailer`, `Upgrade` and `Expect`. These are matched in any
  ASCII case, an underscore counting as a hyphen. Where one is given more than once in different cases,
  the first by byte order among those with a value is sent. Nothing that proves
  who the brain is travels on.
- **The body** is at most 3 MB, in standard base64 with padding and no line
  breaks. The start itself is at most 6 MB, nests at most 1,000 deep, and
  escapes no lone surrogate.
- **A chosen model.** Where a model is chosen for the AI agent, a POST must be
  one UTF-8 JSON object, nested at most 1,000 deep, that names its model once
  as `model` and names exactly that model. A list of models to fall back on
  (`models`) is refused. Where no model is chosen, the body is not read for
  its model.
- **Where these read the body.** A chosen model and an allowance read only the
  body's own top-level fields: the model in `model`, the answer length and
  count in the profile's fields. A provider whose calls name these elsewhere
  cannot use either yet.
- **An allowance** is a limit on what the AI agent's model calls may cost.
  Under one, every POST that is not on a counting route is a model call. It
  must say how long an answer it wants, by the profile's answer-length fields:
  each spelt exactly, given at most once, and a whole number from 1 to 32,768.
  The largest counts. Each of the profile's answer-count fields it gives,
  matched in any ASCII case, must be 1. The body must be one whole UTF-8 JSON
  object, and trailing or truncated data is refused. While an allowance is
  set, the AI agent makes one model call at a time, across all its machines.
- **What is free.** A GET only reads, and a POST on a counting route only
  counts. Neither is held to an allowance: neither is refused, counted or made
  to wait.

### Reading the answer: `GET /api/agent-host/model-calls/{call}?from=N&lease=L`

The answer streams, so the body collects it in parts. Each collection:

- names the run's lease, which may have been renewed since the call began; an
  empty `lease` keeps the one the call has;
- adds `head=1` once it has the status and headers;
- returns at most 2 MB, waiting up to twenty seconds for more.

`from` is read as a base-10 whole number. One that is unreadable or below 0 is
read as 0. A collection refused because the run's lease or the AI agent's
standing does not hold is answered 403 with `"refused": true`, whatever the
cause.

Both the start and every collection answer with:

```json
{
  "call_id":  "the call",
  "status":   200,
  "header":   {"Content-Type": "text/event-stream"},
  "data_b64": "the next part of the provider's answer, base64",
  "next":     1234,
  "done":     false,
  "error":    ""
}
```

`status` and `header` are the provider's. Only the profile's answer headers
travel back, never the ones above. `next` is the offset to collect from next. When `done` is true,
the answer is complete, or `error` says why it ended. A provider that cannot be
reached is not a refusal: its answer ends, done, with an error saying so. An
answer that would carry the key back is stopped before any of it is passed on.
An answer under way is stopped when the AI agent may no longer act.

### Stopping a call: `DELETE /api/agent-host/model-calls/{call}`

The body sends this when its brain gives up on a call. It answers
`{"stopped": true}`.

### Refusals

A refused call is answered with an HTTP status and `{"error": "a sentence the
body passes to its brain"}`. Where the request breaks more than one rule, the
first broken is answered. The Identity Agent's own checks may be answered
before or between them: the lease, the AI agent's standing, how many calls it
holds, and an allowance's state. Fields of a request that the Identity Agent
does not know are ignored.

| Status | When |
|---|---|
| 400 | The request names no lease, or is unreadable |
| 403 | Any of these, and the answer also says `"refused": true`: the method, path, query or model is not one allowed above; the lease is not open for this body; the AI agent may no longer act (revoked, or its grant lapsed); its sign-in is not a key kept here, or has expired or was removed. Under an allowance, also: the allowance is spent; an earlier call ended without its cost being known, which stops the allowance until it is set again; the provider does not say what a call costs; or the call breaks the rules on answer length or number of answers |
| 409 | A collection asks again for part of the answer it has already collected |
| 413 | The start is longer than 6 MB, or the call's body is larger than 3 MB or is not base64 |
| 429 | The machine already holds as many calls for this AI agent as it may, or the Identity Agent holds as many as it may across all its machines; the machine collects their answers first. Under an allowance, also: another of the AI agent's calls is under way or not yet counted, and this one says `"refused": true` |
| 503 | The AI agent's sign-in, what was lent to the run, or its allowance cannot be read right now (a start refused this way also says `"refused": true`); the allowance cannot be written down before the call is sent, so the call was not made; or no address is known here for the provider the key is for |

A call the Identity Agent no longer knows, for example after a restart, is
answered 410 with `"no_call": true`. The body tells its brain the call failed,
and the brain's program makes it again, as it does for any failed call.

## Consequences

- A body never holds an API key, so a compromised body cannot copy one. While a
  run lasts it can still make model calls under the run's lease, within the
  checks above.
- Revoking the AI agent, ending its grant or removing the key stops the next
  call, and an answer under way.
- Every model call crosses the Identity Agent, so a slow or unreachable Identity
  Agent slows or stops the AI agents whose keys it keeps.
- A brain's conversation larger than 3 MB is refused.
- Which calls a provider's key may make is the Identity Agent's list, so a new
  provider needs a profile, not a change to the exchange.
- Under an allowance, a brain whose program does not say how long an answer it
  wants is refused until it does, and the AI agent's calls run one after
  another rather than together.
