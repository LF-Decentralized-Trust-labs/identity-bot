# ADR-079: A Machine Reports Its Own Use, and a Sealed Box Signs Its Report to Its Owner

**Status:** Proposed (2026-11-13)
**Date:** 2026-11-13
**Deciders:** to be decided; the sealed box's report becomes public wire once this ships, and the owner and anyone the owner shows it to check it
**Builds on:** ADR-047 (AI agents talk through the Identity Agent that holds them, over the sealed link)

---

## Context

An owner sizing an AI agent's machine needs to see what it actually uses over time. The host a machine runs on can measure the outside of it (memory the VM holds, CPU time, disk reads and writes) but cannot tell memory held by programs from cache the machine would give back, and for a sealed box it may see nothing else, by design. So the finer figures can only come from the machine itself, and for a sealed box they must reach the owner in a form the host cannot read or change.

## Decision

1. **Two reports, one reading.** A *reading* is one look the machine takes at itself: total memory, memory held by programs (total less what the system says is available), memory held as cache (absent where the system does not say, never zero), the highest program memory since the previous reading, load over 1, 5 and 15 minutes (each absent where the system has none, never zero), disk used and total, and the number of CPU cores. A machine that cannot be read reports nothing; it never reports zero.
2. **An unsealed machine's body reports to the Identity Agent that holds it.** Once a minute it sends its unsent readings (at most 120 a request, at most 3 hours kept while the Identity Agent cannot be reached) as `POST /api/agent-host/usage`, over the sealed, signed link every body uses. The Identity Agent admits it only from an enrolled body, refuses readings it cannot have (programs above total memory, disk used above disk total, a time in the future, spacing under 10 seconds, a flood of them), keeps 30 days per machine, and serves them on `GET /api/mcp/agents/{id}/usage?since=` to the owner, a controller the owner authorised and a granted browser session. The link already says which body spoke, so the reading is not separately signed.
3. **A sealed box signs its own report.** The box keeps its readings in its own sealed storage, and serves `GET /api/machine-usage?since=&nonce=` to its owner (and a controller the owner authorised) over the sealed connection. The answer is `{payload, signature}`: `payload` is the exact JSON text signed, `signature` is the box's identity key over those bytes, in CESR. The payload carries `kind: "machine-usage/1"`, the box's identifier, the caller's nonce, the time signed, the start of the period and the readings.
4. **What a checker verifies** (`identity-agent-core/machineusereport`, `Verify`, with vectors in `machine-usage-vectors.json`): the signature is by the key the caller supplies, which the caller must take from the box's key log (the checker cannot tell whose key it was handed); `kind` is `machine-usage/1`, so a signature made for something else cannot be presented as this; the report names the box the checker means; it carries the nonce the checker asked with (a nonce is required: a checker that supplies none is refused, so an old report cannot pass as a new answer); the period does not start after the signing time; each reading lies in the period (a reading may be at most five minutes after the signing time), later than the one before it, and possible (programs and peak not above total memory, peak not below programs, disk used not above disk total).
5. **The host sees the outside only.** The host's own figures about a machine are shown as the host's, from its own measuring, and are never merged into a box's report. What a sealed box's report carries never passes through the host in a form it can read: it travels the sealed connection to the owner.
6. **Where the code lives.** The report format, its vectors and its checker are public here, because the owner, and anyone shown a report, must be able to verify it. The reading, the sampler, the 30-day store and both routes belong to the add-ons for AI agents and sealed boxes, not the core: not every individual needs them. The core's contribution is what it already has, the sealed link, the owner check, and `SignAsTheIdentity`.

## What a valid report does not show

That the readings are true: they are the box's word, signed, and a compromised box can sign anything. It shows that the box said it, that nobody on the way altered it, and that it was said to this request.

## Consequences

- `identity-agent-core/machineusereport` is new and public; the add-on that serves the box's report must import its types and `Verify` instead of carrying its own copy of the format.
- A box that predates this serves no report; a reader treats the refusal of the route as "no report", not as "no use".
- A new kind of report is a new `kind` string; a checker that does not know it refuses it.
