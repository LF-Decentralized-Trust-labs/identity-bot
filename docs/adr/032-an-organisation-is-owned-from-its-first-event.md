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
- **The organisation can act alone for ordinary work.** It holds its own key.
  What its owner controls is the identity itself: rotating keys, changing who
  owns it, and the decisions that decide what the organisation is.
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
