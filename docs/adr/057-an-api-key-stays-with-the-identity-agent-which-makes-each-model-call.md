# ADR-057 — An API key stays with the Identity Agent, which makes each model call

**Status:** Accepted
**Date:** 2026-10-28
**Amended:** 2026-10-30 — trimmed to the exchange a machine follows. How an Identity Agent that holds AI agents keeps the key, routes the call, caps a machine's calls and records what each call cost is that runtime's own decision, kept with it outside this repository. Also 2026-10-30 — the exchange a machine sees when the Identity Agent holds the AI agent's model calls to an allowance.
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

### Starting a call: `POST /api/agent-host/model-calls`

```json
{
  "lease_id": "the run's lease on the AI agent's sign-in",
  "method":   "POST",
  "path":     "/v1/messages",
  "query":    "beta=true",
  "header":   {"Content-Type": "application/json", "Anthropic-Version": "2023-06-01"},
  "body_b64": "the brain's request body, base64"
}
```

- `path` is the provider's path as the brain sent it. It must be plain and
  short: nothing escaped, no fragment, nothing that cleaning it would change.
  Only the provider's model calls, its list of models, and one model by name
  are made.
- `query` may carry only the parameters a model call uses: `beta=true`, and
  the paging of a list of models.
- `header` carries only `Content-Type`, `Accept`, `Anthropic-Version`,
  `Anthropic-Beta` and `Openai-Beta`. Nothing that proves who the brain is
  travels on.
- The request body is at most 3 MB. A model call is one JSON object naming its
  model once, as `model`. Where a model is chosen for the AI agent, it must name
  exactly that model.
- Where the Identity Agent holds the AI agent's model calls to an allowance (a
  limit on what they may cost), a model call must also say how long an answer
  it wants, as `max_tokens`, `max_completion_tokens` or `max_output_tokens`,
  each spelt exactly and given at most once, a whole number from 1 to 32,768;
  where more than one is given, the largest counts. It asks for one answer:
  `n` and `best_of`, where given, must be 1. While an allowance is set, the AI
  agent makes one model call at a time, across all its machines. A request
  that only reads, such as listing the provider's models or reading one model,
  is not held to the allowance at all: it is not refused, counted or made to
  wait.

### Reading the answer: `GET /api/agent-host/model-calls/{call}?from=N&lease=L`

The answer streams, so the body collects it in parts. Each collection names
the run's lease, which may have been renewed since the call began; adds
`head=1` once it has the status and headers; and returns at most 2 MB, waiting
up to twenty seconds for more.

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

`status` and `header` are the provider's. `next` is the offset to collect
from next. When `done` is true the answer is complete, or `error` says why it
ended. An answer that would carry the key back is stopped before any of it is
passed on, and an answer under way is stopped when the AI agent may no longer
act.

### Stopping a call: `DELETE /api/agent-host/model-calls/{call}`

The body sends this when its brain gives up on a call. It answers
`{"stopped": true}`.

### Refusals

A refused call is answered with an HTTP status and `{"error": "a sentence the
body passes to its brain"}`:

| Status | When |
|---|---|
| 400 | The request names no lease or no call to make |
| 403 | The lease is not open for this body, the AI agent may no longer act (revoked, its grant lapsed), its sign-in is not a key kept here or has expired or was removed, or the path, query or model is not one allowed above. Under an allowance, also: the allowance is spent; an earlier call ended without its cost being known (the provider answered it without saying what it cost, it was lost in a restart, or its cost could not be written down), which stops the allowance until it is set again; the provider does not say what a call costs; or the call breaks the rules above on answer length or the number of answers, or is not one JSON object. A start or a collection refused this way also says `"refused": true` |
| 409 | A collection asks for part of the answer from before `from` it already collected: that part was let go and cannot be given again |
| 413 | The call is larger than 3 MB, or unreadable |
| 429 | The machine already holds as many calls for this AI agent as it may; it collects their answers first. Under an allowance, also: another of the AI agent's calls is under way or not yet counted, and this one says `"refused": true` |
| 503 | The AI agent's sign-in, what was lent to the run, or its allowance cannot be read right now (a start refused this way also says `"refused": true`); the allowance cannot be written down before the call is sent, so the call was not made; or the provider the key is for cannot be reached from here right now |

A call the Identity Agent no longer knows, for example after a restart, is
answered 410. The body tells its brain the call failed, and the brain's
program makes it again, as it does for any failed call.

A body that does not say, when it borrows a sign-in, that it makes its brain's
model calls through the Identity Agent is refused and told to update. It is
never lent the key.

## Consequences

- A body never holds an API key, so a compromised body cannot copy one. While a
  run lasts it can still make model calls under the run's lease, within the
  checks above.
- Revoking the AI agent, ending its grant or removing the key stops the next
  call, and an answer under way.
- Every model call crosses the Identity Agent, so a slow or unreachable Identity
  Agent slows or stops the AI agents whose keys it keeps.
- A brain's conversation larger than 3 MB is refused.
- Under an allowance, a brain whose program does not say how long an answer it
  wants is refused until it does, and the AI agent's calls run one after
  another rather than together.
