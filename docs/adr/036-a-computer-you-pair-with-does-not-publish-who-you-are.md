# ADR-036 — A computer you pair with does not publish who you are

**Status:** Accepted
**Date:** 2026-08-12
**Builds on:** ADR-032 (an identity can name who owns it, from its first event),
ADR-034 (an instance is told who may claim it, before anyone can reach it)

## Context

A person pairs a computer with their Identity Agent so it can hold their data
and stay reachable when their phone is not. The computer needs an identity of
its own, and that identity needs to answer to them.

The implementation made it a **delegated** identity: a KERI delegated inception
(`dip`), with the person's own root identifier as the delegator.

A delegated inception names its delegator in its own event, and that event is
served to anybody who asks — no credential, no relationship, no permission.
That is not a defect in KERI. It is the entire point of a delegation: a third
party who trusts neither side has to be able to see the claimed parent in order
to go and check it.

The consequence is what this ADR is about. Fetched from a running paired
computer:

```
event type : dip
delegator  : E…                  ← the owner's root identifier
this agent : E…
```

**A root identifier is the one string that identifies a person in every
relationship they have, permanently.** Nothing signs with it and nothing is
unlocked by it, so this is not a stolen key. It is worse in a quieter way:
anyone who can reach the address of somebody's computer learns the identifier
that lets them recognise that person everywhere else it appears, and it never
rotates.

So pairing a computer — the thing recommended to most people — published the
identifier we work hardest everywhere else to keep pairwise.

**And it bought nothing.** No code anywhere fetched the delegator's key event
log to verify the anchor. Both sides discarded the anchoring event after
pairing completed. The verifiability that delegation charges for was never
collected: the cost was paid in full and the benefit was zero.

## Decision

**A computer you pair with founds its own root and names a pairwise identity of
yours as its owner.**

The mechanism is the one ADR-032 already established — an inception carrying an
owner seal — used with a different identifier in the seal:

1. **The computer's identity is its own root** (`icp`, not `dip`). There is no
   delegator field, so there is nothing naming a parent in what it publishes.

2. **The owner named in the seal is derived for that one computer.** It comes
   from the same root seed by hierarchical derivation, so it is recoverable from
   the recovery phrase alone and needs no extra backup, but it is a distinct
   identifier that appears in no other relationship. Two computers owned by one
   person share nothing an observer can join.

3. **The owner identity is minted before the computer is asked for.** ADR-034
   requires the instance to be told who may claim it before it is reachable, so
   the identifier has to exist before the request that creates the machine. It
   is minted first, sent as the prospective owner, and named again when pairing
   completes. The two must match or the computer would trust an owner its
   operator cannot sign as.

4. **The derivation index is recorded when the identity is minted.** An owner
   identity whose index was lost can never be re-derived, which means never
   signing to that computer again — no rotation, no revocation, no recovery. It
   is stored at mint time rather than reconstructed later.

### What this costs

**Nobody outside can verify who owns the computer.** With a delegation, a third
party could walk from the parent to the child. Now the seal names an identifier
that means nothing to them. This is deliberate: for a personal computer, that
verifiability is not wanted by anybody and was not being used by anything.

**"All my computers" is not a public fact.** The owner still knows — each index
is recorded locally and covered by the recovery phrase — but no observer can
group them, which is the property being bought.

## Pairing and delegation are the two ceremonies

The name now carries the answer, so the mechanism is not re-argued each time:

- **Pairing** — the computer founds its own root and names a **pairwise**
  identity of yours as owner. Nothing about you is published. A computer a
  person pairs with is this, and it is the default.
- **Delegation** — the identity is a `dip` and the delegator **is** published,
  because something running there is meant to be provably yours to a third
  party. An organisation's website, its published services, an AI agent acting
  in its name: the lineage is the product, so publishing it is the feature.

Two questions decide which, and only two:

1. **Is this relationship meant to be known?** Delegation publishes the parent
   permanently and to anybody. That is the feature for an organisation's
   properties and the defect for a person's computer.
2. **Must authority move without destroying the identity?** A delegation cannot
   be transferred, only destroyed. Anything that must survive a change of who
   controls it cannot be a delegation.

**Authority is not one of the questions.** Being delegated says who you belong
to, never what you may do. Permissions are granted by credentials, which name
specific things, can be disclosed selectively, and can be revoked one at a time.
Credentials express authority; identity answers who. Reading lineage as
permission collapses that boundary and is the mistake this note exists to
prevent.

**Nor is where the key is generated.** A computer that mints its own key can be
either shape — delegated over that key, or founding its own root and naming an
owner. It is an implementation constraint, not a decision input.

## Consequences

- **Derivation pools must not overlap.** Pairwise identities are derived per
  purpose, and each purpose needs its own range of indices. A new pool that
  starts at index 1 like every other pool re-derives an identifier already in
  use elsewhere — the same seed and the same index give the same key. This was
  not hypothetical: adding the pool for owner identities produced, on its first
  use, an identifier already serving as an organisation's owner. Each pool now
  has an explicit range, a pool with no range assigned is **refused** rather
  than defaulted to the first one, and a test fails if two ranges ever overlap.
  The refusal immediately surfaced a second pool that had been silently sharing
  a range with the first.
- **What a machine signs as is recorded under a name that says so.** The column
  was `delegated_aid`; it is `signs_as_aid`. The value was always right, but the
  name is what the next person reads before changing pairing, and
  `delegated_aid` teaches them that a delegation is what happens here. It is
  named for what it holds rather than for the ceremony, so it stays honest if a
  delegated machine is ever recorded alongside.
- **An owner identity this device never minted is refused at pairing.** A
  computer paired under an identifier we hold no key for would answer to nobody
  and could never be reached again. It fails with that as the reason.
- **The delegated path is still implemented, and should stay.** Pairing never
  routes through it, but `handlePairingComplete` still accepts a `dip` for the
  cases where a published lineage is the point — an organisation's website, its
  services, an AI agent acting in its name. It is not dead code awaiting
  removal, and it is not a shortcut for a personal machine. Anyone tempted to
  "simplify" by sending machines back through it should read the Decision above
  first.
- **The route name still says "adopt".** `/api/pairing/adopt` predates this
  decision. Renaming it would break every already-paired computer for no
  behavioural gain, so it stays; "adopt" on the wire means pairing as described
  here.
- **Nothing had to be migrated.** No delegated computer existed outside testing
  when this changed.

## Alternatives considered

**Keep the delegation and stop publishing the event.** Not possible without
breaking KERI: the delegator is inside the inception event, the event's
identifier is derived from its own content, and the event is what a key event
log serves. There is no version of a delegated identity that does not name its
delegator.

**Delegate from a pairwise identity instead of the root.** This hides the root
and keeps a verifiable chain. Rejected because it keeps the property that made
delegation wrong here — a delegation cannot be transferred, only destroyed — for
a benefit nothing consumes. A computer must be replaceable without destroying
it.

**Leave it and rely on the address being hard to find.** The address is
published on purpose; being reachable is what an always-on Identity Agent is
for.
