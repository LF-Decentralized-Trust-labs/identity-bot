# ADR-044 — An authorized controller does the application's work; the owner key does the root of trust

**Status:** Accepted
**Date:** 2026-10-18
**Relates to:** ADR-042 (How an agent is reached, and who may manage it), ADR-038 (Who claims a machine is not who owns what it founds), ADR-027 (Hardware-gated signing-key custody)

## Context

An Identity Agent is often operated through a front end that is not the machine
holding the identity's key. The owner may sit at a **controller** — a paired
computer, or the owner's own app — that reaches a full Identity Agent running
elsewhere. This is
the ordinary case, not an edge case.

The router-wide authorization gate (`authorize` in `server/api_auth.go`) already
accounts for it: an owner-level route is served when the request is the owner
(`isOwner`), **or** when it comes from the owner's authorized controller
(`controllerActsForTheOwner`, gated by the deny-list in
`server/what_a_controller_may_reach.go`), or from a browser session the owner
approved. The controller model is a **deny-list**: a controller may reach any
route that is not explicitly closed, so a route added later works for the owner's
own front end without anyone granting it — the opposite of an allow-list, and
deliberately so (an owner's front end should never be the one caller that cannot
use a capability an outside AI agent can).

But a number of handlers *also* re-checked `isOwner` directly, as the first thing
they did — a stricter, pre-gate test left over from before the router-wide gate
existed. `isOwner` is only true for a request that originates on the machine
itself, is sealed by the owner's own identity, or is signed with the owner key.
A controller reaching the Identity Agent over the network is none of those. So these
handlers refused the owner's own authorized front end even though the gate had
already admitted it — the owner, reaching their own Identity Agent through the very
mechanism built for it, was locked out of ordinary application work: creating and
managing a delegated AI-agent identity, minting its bounded token, reading the
capability registry.

## Decision

Authority has **two tiers, divided by what an operation touches** — not by which
handler it lives in.

**Root of trust — the owner key is required.** Anything that writes the state the
authorization decision itself later reads: the root seed, the identity record, the
owner-authority anchor, key events, signing as the owner of a machine, and the
controller-enrollment state. These stay owner-only — the closed group in
`what_a_controller_may_reach.go` plus the owner checks in their handlers. **A
controller may never write what decides who the owner is**, because a caller that
could do that could make itself the owner and open every other gate (the
escalation the policy file documents).

**Application operations — an authorized controller may do them.** Everything else:
the day-to-day work of running the Identity Agent. The authorized controller reaches these
through the router-wide gate, and **the handler adds no second owner-only check.**

Concretely, these are application operations an authorized controller may perform:
provisioning and managing a delegated AI agent identity; minting, listing and revoking
that AI agent's bounded token; and reading the capability registry. **Defining new
capabilities — importing a capability pack — remains owner-only**, because a pack
declares the host-control and egress properties the gateway reads when it authorizes
an invocation; importing one writes authorization-decision state, so it belongs with
the root of trust.

**Minting a durable credential is raised to the verified level.** A few of these
application operations create a credential that outlives the request that made it:
provisioning an AI agent and minting its bearer token, re-issuing an AI agent's
capability grant, and changing its configuration — which model it reaches, with which
stored key. These are reached only by a controller that has proven the verified
authentication level, and never by a browser session — matching how issuing a
credential is treated, because a time-bounded session or controller compromise must
not be able to leave behind standing access that survives it. This is a
strength-of-authentication requirement, not a narrowing of what the controller may
do: the owner's authorized controller reaches that level the same way it does to
issue a credential.

**The gate, not the handler, decides authority.** The redundant in-handler `isOwner`
checks on application operations are removed. This makes the handlers consistent with
the gate and removes a second copy of the authority policy that would otherwise drift
from the one the gate enforces.

*Amended 2026-10-22.* **A controller's grant is a credential as well as a record.** When a
machine is granted, the identity also issues it a Controller Grant (ADR-045) into its own
registry: the machine's key, label, grade, the signer it acts as, and its expiry. The
issuance is anchored in the identity's key log, so that the machine was authorised, and as
whom, can be shown to anybody without asking this Identity Agent. A grant that cannot be
anchored is not made. Removing the machine also revokes its credential; the machine stops at
once even when that revocation cannot be written. Settling which signer a machine acts as
re-issues its credential to say so. What is done from the machine names this credential
(ADR-045, ADR-047).

## Consequences

- The owner's authorized controller can do the application's work without the owner
  key signing each action. The owner key is reserved for the root of trust, where it
  belongs.
- An unauthorized caller is unaffected: the gate still denies it, and a controller
  still cannot write anything the authorization decision reads.
- The authority model is asserted in one place — the gate's route policy — rather
  than scattered across handler bodies.
- This is the single-controller model. A deployment with several distinct roles
  (different people allowed different subsets of the application) is a further
  refinement layered on top of this tier split, not a change to it: the root-of-trust
  line stays exactly where this ADR draws it.

## Scope

This ADR governs **who may invoke an operation**. What an AI agent's grant contains,
and how it is issued and verified, is ADR-045.
