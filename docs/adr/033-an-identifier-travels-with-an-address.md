# ADR-033: An identifier travels with an address

**Status:** Accepted
**Date:** 2026-07-31

## The decision

**When one agent gives another its AID, it normally gives the URL where that AID
can be reached at the same time. The two travel together.**

The address is called the **agent URL**. On the wire it is `agent_url`, or
`<role>_agent_url` where the role needs naming — `owner_agent_url`,
`signer_agent_url`.

The one case that does not need it is a **one-way relationship**: where only the
identifier's owner ever initiates, and the other party never needs to start a
conversation. Then an AID alone is enough, and asking for an address would be
collecting something that will never be used.

Everything else needs both.

## Why this needs saying at all

An AID says **who somebody is**. It says nothing about **how to reach them**.

That sounds obvious written down, and it has not been obvious in practice —
because for most of this system's life the two have been conflated by
circumstance. An OOBI carries both, so anywhere an OOBI is exchanged the
question never arises. It arises the moment one party holds only an identifier
and needs to send something the other party did not ask for.

That case is now real. A device enrolled to an owner may need to raise something
unprompted — a deadline, a state change, a condition the owner did not ask about
and cannot be expected to poll for. It holds the owner's AID and, until now, had
no way to reach them.

The resolution path exists in the core and is not wired into any send path:

- `PublishEndpointLocation` (`server/endpoint_publish.go`) publishes a
  `/loc/scheme` reply to an AID's witnesses.
- `RecoverContactEndpoint` (`server/endpoint_recover.go`) reads it back.
- `SendDIDCommMessage` (`server/didcomm_agent.go`) does neither, and instead
  requires a peer registered out of band with an `endpoint` somebody typed in.

So resolution is the right long-term answer and is not available today. A party
that could only *sometimes* find an address would reach only some of the people
it needs to, silently, and would discover which at the worst possible moment.
Carrying the address explicitly is what makes the failure happen at the door.

## The address is pairwise

An agent URL is scoped to a relationship the same way an AID is.

A single stable address handed to every party would be a correlation handle: two
parties comparing notes would learn they are talking to the same agent, which is
precisely what pairwise identifiers exist to prevent. Giving out one identifier
per relationship and one address for all of them would undo the identifier work
at the transport layer.

So the address is issued per relationship, and an agent URL is not evidence of
anything about any other relationship.

## What follows from this

**Ask for it at the door, not at the moment of sending.** Validate that it
parses, that its scheme can actually carry a message, and that it is not
plaintext except against loopback. Discovering an address is unusable at the
moment you need it is discovering it too late — and the moments you need it are
disproportionately the urgent ones.

**Absence is a decision, not an oversight.** A protocol that omits the address
should say it is one-way and why. Otherwise the next person to need a
back-channel has to guess whether it was left out deliberately.

**It is not a shared module.** Two lines of validation, and a name used
consistently. A package to hold that would cost more to depend on than to
rewrite.

## Consequences

Every contract carrying an AID for a two-way relationship gains a sibling field.
Where that is a wire format already in use, adding it is additive and optional
until a version that requires it.

When witness-based resolution is wired into the send path, the explicit address
becomes a fallback rather than the only mechanism. It should stay: a party whose
witnesses are unreachable is exactly the party you still need to warn.

## Related

- ADR-021 — where integration surfaces live
- ADR-031 — who witnesses what, and where a `/loc/scheme` record is published
