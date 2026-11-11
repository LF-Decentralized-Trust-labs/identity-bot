# ADR-073: An Authentication Statement Names the Identity Agent It Is For

**Status:** Proposed
**Date:** 2026-11-11
**Deciders:** Rob Andersen
**Amends:** ADR-050 (One Check for Controller Actions and AI Agent Capability Calls)

---

## Context

The device that holds an identity's root key tells an Identity Agent how well
somebody was authenticated by signing a statement, and a controller (a laptop)
relays it. The statement named the controller and the moment, so one made for a
laptop could not be relayed by another machine. It did not name the Identity
Agent. A person who holds two identities on one root device, and works on both
from one laptop, produced statements that either agent would accept.

## Decision

1. **The statement names the Identity Agent.** The text signed is now
   `IA-AUTH-LEVEL-V2`, then each of these on its own line: the Identity Agent's
   identifier, the controller's identifier, the level, the time (RFC 3339, UTC),
   and the score.
2. **An Identity Agent checks it against its own identifier.** A statement made
   for another Identity Agent fails the signature and the level is treated as
   unmeasured. An Identity Agent that has no identifier yet (a machine sealed
   before it had an identity) uses an empty first line, so a statement for an
   identified agent never fits it.
3. **`IA-AUTH-LEVEL-V1` is no longer accepted.** A signer that still produces it
   is read as unmeasured until it signs `V2`.

## Test vector

    IA-AUTH-LEVEL-V2
    EAgent
    BController
    authenticated
    2026-11-11T09:30:00Z
    80

(joined by `\n`, no trailing newline). It is checked by
`TestTheAuthLevelStatementHasOneFixedForm` in `identity-agent-core/server`, and a
statement for a different agent is refused by
`TestAStatementForAnotherAgentIsNotBelieved`. The Dart client only relays the
signature (`VouchedAuthentication.vouchedBy`) and never builds the text, so it has
no second copy to keep in step.

## Consequences

- Whoever signs these statements (the device holding the root key) must put the
  Identity Agent's identifier in. It learns it from the controller's
  `/api/controller/agent` answer.
- No client signs these statements yet, so until one does, a controller's
  authentication is always read as unmeasured. The signer, when it is built,
  is held to the test vector above.
- A statement is still not bound to one request (ADR-050): a controller
  compromised during its short window can spend it.
