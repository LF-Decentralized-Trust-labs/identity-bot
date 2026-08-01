# ADR-032 — An organisation is owned from its first event

**Status:** Accepted
**Date:** 2026-07-31
**Supersedes:** the central decision of ADR-030

## Context

An organisation has no mind. It cannot decide, consent, or be held to anything.
Whatever a company does, some person decided it — and in law that is not a
technicality but the whole basis on which a company can act at all. Companies do
not spontaneously come into being; a person brings one into being and answers
for it.

So an organisation's identity cannot be self-owned. If the software running an
organisation holds the only key to that organisation, then the organisation
owns itself, and there is nobody the identity ultimately answers to. That is not
an organisation. It is an unattended key.

The implementation had drifted into exactly that. An organisation's identity was
created first and its owner recorded afterwards, in a file beside the database.
Three consequences followed, and all three were reachable:

- **A window with no owner.** Between creating the identity and recording an
  owner, the organisation answered to itself — and nothing required the second
  step ever to happen. An organisation with no owner was indistinguishable from
  one that owned itself, at every point in the code that asked.
- **Ownership could be silently replaced.** The record was a file. A second
  owner overwrote the first, who was left listed as an administrator with no
  cryptographic standing at all — a name in a table.
- **Ownership was invisible.** Nobody outside the machine could verify who owned
  an organisation, because the answer lived on that machine's disk.

ADR-030 identified the same problem and proposed that an organisation's identity
BE its owners' keys: no identity until they sign. That solves the ownership
question and creates a worse one. An organisation whose only keys are its
owners' cannot do anything without them — it cannot answer a routine request,
maintain a relationship, or keep its own address current, because every one of
those is a signature. It also has no defined existence while signatures are
being collected.

## Decision

**An organisation creates its own identity, and names its owner in the same
event that creates it.**

Concretely, three things together:

1. **The organisation has its own key.** A plain inception, and the identity is
   its own. It can do its own day-to-day work — hold relationships, serve
   discovery, keep its address current — without reaching for a person every
   time.

2. **The owner is anchored in that inception event.** The event carries a seal
   naming the owner's identifier. Ownership is therefore part of the key event
   log: append-only, public, and verifiable by anyone who can read the log.

3. **The owner is a per-relationship identifier, not a delegation.** The person
   who founds an organisation mints an identifier for that organisation
   specifically, and that is what the anchor names.

There is exactly one owner at inception, always. More can be added afterwards by
rotation, which changes the anchored set. That is a separate ceremony and can
take as long as the people involved need, because the organisation is fully
working throughout.

## Why not a delegation

A delegated identity carries its delegator inside it. That is the right shape
for a relationship which is permanent by nature — a device belonging to a
person, an agency belonging to a government.

It is the wrong shape for a company, because **a delegation cannot be
transferred. It can only be destroyed.** Selling a delegated organisation would
mean killing its identity, and with it every credential it ever issued, every
relationship it ever formed, and every signature anyone ever relied on. The
buyer would receive a name and a fresh start.

With the owner anchored rather than delegated, ownership changes by rotation.
The organisation keeps its identifier, its history and its relationships, and
the people who own it change. A company outliving its founder is not an edge
case; it is the ordinary life of a company.

## Why the anchor rather than a record

Both a file and an anchor can say who owns an organisation. Only one of them can
be trusted.

| | A file | An anchor in the log |
|---|---|---|
| Can be replaced silently | yes | no — a log only appends |
| Visible outside the machine | no | yes |
| Survives the machine | no | yes |
| Says when ownership began | only if it says so | inherently — it is an event |

The failure that motivated this was not hypothetical. A second owner replacing
the first was a single file write, invisible to everyone including the first
owner. As an anchor it is a rotation event: it happens in the open, in order,
and permanently.

## Consequences

- **There is no unowned organisation.** Not because something checks, but
  because the owner is named in the event that brings the identity into
  existence. There is no earlier moment to be unowned in.
- **Ownership is verifiable by anyone**, from the log, without trusting the
  machine the organisation runs on. This matters most when the organisation runs
  on hardware somebody else operates.
- **Changing owners is an event, not an edit.** It is ordered, attributable and
  permanent, and a previous owner's standing is a matter of record rather than
  of whether a file was overwritten.
- **An organisation can be sold**, because ownership was never built into its
  identity.
- **The organisation can act alone for ordinary work** — see the amendment
  below, which says what that means concretely.
- Provisioning must carry the intended owner. An organisation cannot be created
  without one, so the request that creates it has to say who.

## What this changes from ADR-030

ADR-030 remains right that an organisation must answer to people, and its
account of why an unowned organisation is a defect stands. What is superseded is
the mechanism: an organisation is not the same thing as its owners' key set, and
does not wait on their signatures to exist. It has its own key and names its
owner in its first event.

The parts of ADR-030 that were implemented and remain correct: recording the
owner before writing any roster, refusing an owner record with no key material,
and carrying next-key digests on multi-signature inception so such an identity
can rotate at all.

---

# Amendment — 2026-07-31, later the same day

The decision above is right about *why* an organisation is not delegated. It was
wrong about the shape, and the error was over-correction: rejecting delegation
for the organisation, it also threw out a delegation the design depended on.

## The correction: two identifiers, not one

**The organisation's root identity is multi-signature over its owners.** One
owner at founding, so one-of-one. Owners are added by rotation, so it becomes
m-of-n. It is not delegated, so it can be sold — that reasoning stands
unchanged.

**The root delegates an operating identity**, which is a single key living on
the always-on machine. That identity does the day-to-day work: holding
relationships, issuing credentials, hiring, serving discovery. It is
replaceable, and replacing it is a root decision.

This is the same shape used everywhere else in the system. A person's root key
lives on their phone and a delegated key lives on their computer; the computer
is replaceable and the person is not. An organisation is that arrangement with
the root being multi-signature over several people instead of one.

## Why one identifier could not work

With a single identifier there is no way to have both properties at once.
Ordinary work anchors events in the organisation's key log — so if the
organisation's only key is m-of-n, issuing a credential needs a quorum of
humans. Either the owners sign everything, which makes an organisation
unusable, or they sign nothing, which makes ownership decorative.

Splitting the identifier is what resolves it. The threshold guards the root; the
operating key does the work; and the root's involvement is bounded to the events
that decide what the organisation *is*.

## What the owners must sign

| Action | Threshold |
|---|---|
| Bring the organisation into existence | yes |
| Add or remove an owner; change the threshold | yes |
| Rotate the root key | yes |
| Revoke or replace the operating identity | yes |
| Hire, scope or revoke a member | no |
| Issue or revoke a credential | no |
| Anything a member does within their scope | no |

This replaces the phrase "the decisions that decide what the organisation is",
which was too vague to implement and therefore decided nothing.

## Why this scales

The owners sign a fixed number of times: once to found, once per operating
identity, once per ownership change. Everything else is delegated *by the
operating identity*, so an organisation adding its fiftieth department or its
ten-thousandth member never convenes its owners.

The alternative — hanging every machine and department directly off the root —
costs a quorum per addition, because a delegator anchors each delegation it
issues. One operating identity that parents everything below it is what keeps
the owners' involvement constant rather than proportional to the size of the
organisation.

Two things make this hold in practice, and both are already true: credentials
are issued into a transaction event log registry created once per issuer, so the
key log grows with structure rather than with activity; and the delegation chain
stays shallow, because a verifier walks every link.

The trade, stated plainly: the operating identity becomes a single point of
compromise for everything beneath it, and only the owners can revoke it. That is
what is bought by not requiring them to sign day-to-day work. It is mitigated by
that key living on attested hardware and by revocation being an owner action —
not eliminated.

## Binding the owners' terms at rotation

An organisation may want more than the table above — that a particular
capability, appointment or account also requires the owners. Because a rotation
event carries arbitrary data, the terms can be written into the rotation that
establishes them: anchored in the log, signed by the threshold that agreed them,
and changeable only by another rotation the threshold signs.

That gives three real properties. The terms cannot be altered without the
owners. Anyone can verify what they are and when they changed. And the machine
cannot quietly rewrite them, which is exactly the failure that put ownership in
the log in the first place.

One limit worth stating rather than discovering: a key event log proves who
signed and what was agreed. It does not execute policy. For the identity-plane
actions in the table the enforcement *is* cryptographic — the machine does not
hold enough keys to perform them. For anything else, the terms are tamper-proof
and their enforcement is the gateway reading them. Not built yet; recorded here
so the mechanism is not reinvented.

## What this supersedes

- **This ADR's own consequence** that the organisation "holds its own key" as a
  single identity. It holds an operating key, delegated from a multi-signature
  root.
- **ADR-030's** claim that an organisation cannot act without the threshold. The
  root cannot; the operating identity can, and must.

The two-identifier model itself is not new. It was written down, withdrawn in
the belief that it conflicted with transferability, and is reinstated here
because it does not: what must never be delegated is the organisation. An
operating identity delegated *by* the organisation is a different thing, and
revoking it is already an owner's decision.
