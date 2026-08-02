# ADR-032 — An identity can name who owns it, from its first event

**Status:** Accepted
**Date:** 2026-07-31 · amended 2026-08-01
**Supersedes:** the central decision of ADR-030

## Context

Some identities answer to somebody other than themselves.

An identity created for a child answers to whoever holds guardianship. An
identity representing a group answers to the people in it. A device's identity
answers to whoever owns the device. In each case the identity has its own key
and does its own work — but there is somebody it ultimately answers to, and that
fact needs to be true in a way anyone can check.

The implementation recorded it in a file beside the database, written after the
identity already existed. Three consequences followed, and all three were
reachable:

- **A window with nobody.** Between creating the identity and recording who it
  answered to, it answered to itself — and nothing required the second step ever
  to happen. An identity that answered to nobody was indistinguishable from one
  that was meant to, at every point in the code that asked.
- **It could be silently replaced.** The record was a file. A second party
  overwrote the first, who was left with no cryptographic standing at all — a
  name in a table.
- **It was invisible.** Nobody outside the machine could verify who an identity
  answered to, because the answer lived on that machine's disk.

ADR-030 proposed that such an identity BE its owners' keys: no identity until
they sign. That solves the ownership question and creates a worse one. An
identity whose only keys are its owners' cannot do anything without them — it
cannot answer a routine request, maintain a relationship, or keep its own
address current, because every one of those is a signature. It also has no
defined existence while signatures are being collected.

## Decision

**An identity that answers to somebody names them in the event that creates
it.**

Concretely, three things together:

1. **The identity has its own key.** A plain inception, and the identity is its
   own. It can do its own day-to-day work — hold relationships, serve discovery,
   keep its address current — without reaching for a person every time.

2. **The owner is anchored in that inception event.** The event carries a seal
   naming the owner's identifier. Ownership is therefore part of the key event
   log: append-only, public, and verifiable by anyone who can read the log.

3. **The owner is a per-relationship identifier, not a delegation.** Whoever
   brings an identity into being mints an identifier for that relationship
   specifically, and that is what the anchor names.

**One owner or several, from the start.** An identity created for a child
answers to whoever holds guardianship, which is frequently two people rather
than one; anything created jointly is the same shape. The set changes afterwards
by rotation, which is a separate ceremony and can take as long as the people
involved need, because the identity is fully working throughout.

## Why not a delegation

A delegated identity carries its delegator inside it. That is the right shape
for a relationship which is permanent by nature — a device belonging to a
person, a subordinate identity that should not outlive its parent.

It is the wrong shape wherever the relationship must be able to **change
hands**, because **a delegation cannot be transferred. It can only be
destroyed.** Transferring one would mean killing the identity, and with it every
credential it ever issued, every relationship it ever formed, and every
signature anyone ever relied on. The recipient would get a name and a fresh
start.

With the owner anchored rather than delegated, ownership changes by rotation.
The identity keeps its identifier, its history and its relationships, and the
people who own it change. An identity outliving the arrangement it was created
under is not an edge case: a guardianship ends, a group's membership turns over,
a resource is handed on.

## Why the anchor rather than a record

Both a file and an anchor can say who owns an identity. Only one of them can be
trusted.

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

## The rule that keeps it honest

**An identity founded without an owner can never acquire one.**

A later event may reorganise a set that exists. It may not conjure one where
there was none, because that is precisely the silent claim of ownership the
anchor was built to make impossible. Founded unowned means unowned forever, and
the remedy is to found it again rather than to append a claim.

Nor can an identity rotate itself to having no owners. Answering only to itself
is the state this mechanism exists to make unreachable, and reaching it by
subtraction is still reaching it.

## Consequences

- **There is no window with nobody.** Not because something checks, but because
  the owner is named in the event that brings the identity into existence. There
  is no earlier moment to be unowned in.
- **Ownership is verifiable by anyone**, from the log, without trusting the
  machine the identity runs on. This matters most when it runs on hardware
  somebody else operates.
- **Changing owners is an event, not an edit.** It is ordered, attributable and
  permanent, and a previous owner's standing is a matter of record rather than
  of whether a file was overwritten.
- **Such an identity can change hands**, because ownership was never built into
  the identifier.
- **The identity can act alone for ordinary work.** It holds its own key. What
  its owners control is the identity itself — see the amendment for what that
  means concretely.
- Whatever creates such an identity must carry the intended owner. It cannot be
  created without one, so the request that creates it has to say who.

## What this changes from ADR-030

ADR-030 remains right that an identity of this kind must answer to people, and
its account of why an unowned one is a defect stands. What is superseded is the
mechanism: such an identity is not the same thing as its owners' key set, and
does not wait on their signatures to exist. It has its own key and names its
owners in its first event.

The parts of ADR-030 that were implemented and remain correct: recording the
owner before writing any roster, refusing an owner record with no key material,
and carrying next-key digests on multi-signature inception so such an identity
can rotate at all.

---

# Amendment — 2026-08-01

The decision above is right about *why* such an identity is not delegated. It
was wrong about the shape, and the error was over-correction: rejecting
delegation for the identity itself, it also threw out a delegation the design
depended on.

## The correction: two identifiers, not one

**The root identity is multi-signature over its owners.** One owner is
one-of-one; more are added by rotation, so it becomes m-of-n. It is not
delegated, so it can change hands — that reasoning stands unchanged.

**The root delegates an operating identity**, a single key doing the day-to-day
work: holding relationships, issuing credentials, serving discovery. It is
replaceable, and replacing it is a decision for the root.

This is the same shape used elsewhere in the system. A person's root key lives
on their phone and a delegated key lives on their computer; the computer is
replaceable and the person is not.

## Why one identifier could not work

With a single identifier there is no way to have both properties at once.
Ordinary work anchors events in the identity's own key log — so if its only key
is m-of-n, issuing a credential needs a quorum of humans. Either the owners sign
everything, which makes the identity unusable, or they sign nothing, which makes
ownership decorative.

Splitting the identifier resolves it. The threshold guards the root; the
operating key does the work; and the owners' involvement is bounded to the
events that decide what the identity *is*.

## What the owners must sign

| Action | Threshold |
|---|---|
| Bring the identity into existence | yes |
| Add or remove an owner; change the threshold | yes |
| Rotate the root key | yes |
| Revoke or replace the operating identity | yes |
| Anything the operating identity does within its remit | no |

This replaces a phrase — "the decisions that decide what the identity is" —
which was too vague to implement and therefore decided nothing. Exactly what
falls in the last row is a policy question, and policy is not settled here.

## Why this scales

The owners sign a fixed number of times: once to found, once per operating
identity, once per ownership change. Everything else is delegated *by the
operating identity*, so an identity acquiring its fiftieth subordinate resource
never convenes its owners.

The alternative — hanging everything directly off the root — costs a quorum per
addition, because a delegator anchors each delegation it issues. One operating
identity that parents everything below it keeps the owners' involvement constant
rather than proportional.

Two things make this hold in practice: credentials are issued into a transaction
event log registry created once per issuer, so the key log grows with structure
rather than with activity; and the delegation chain stays shallow, because a
verifier walks every link.

The trade, stated plainly: the operating identity becomes a single point of
compromise for everything beneath it, and only the owners can revoke it. That is
what is bought by not requiring them to sign day-to-day work. It is mitigated by
that key living on attested hardware and by revocation being an owner action —
not eliminated.

## Binding terms at rotation

An owner set may want more than the table above — that a particular capability
or action also requires them. Because a rotation event carries arbitrary data,
the terms can be written into the rotation that establishes them: anchored in
the log, signed by the threshold that agreed them, and changeable only by
another rotation the threshold signs.

That gives three real properties. The terms cannot be altered without the
owners. Anyone can verify what they are and when they changed. And the machine
cannot quietly rewrite them, which is the failure that put ownership in the log
in the first place.

One limit worth stating rather than discovering: a key event log proves who
signed and what was agreed. It does not execute policy. For the actions in the
table the enforcement *is* cryptographic — the machine does not hold enough keys
to perform them. For anything else the terms are tamper-proof and their
enforcement is whatever reads them.

## What this supersedes

- **This ADR's own consequence** that the identity "holds its own key" as a
  single identity. It holds an operating key, delegated from a multi-signature
  root.
- **ADR-030's** claim that such an identity cannot act without the threshold.
  The root cannot; the operating identity can, and must.

The two-identifier model is not new. It was written down, withdrawn in the
belief that it conflicted with transferability, and is reinstated here because
it does not: what must never be delegated is the root. An operating identity
delegated *by* it is a different thing, and revoking it is already an owner's
decision.
