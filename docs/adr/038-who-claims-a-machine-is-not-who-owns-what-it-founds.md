# ADR-038 — Who claims a machine is not who owns what it founds

**Status:** Accepted
**Date:** 2026-08-30
**Builds on:** ADR-032 (an identity can name who owns it, from its first event),
ADR-034 (an instance is told who may claim it, before anyone can reach it),
ADR-036 (a computer you pair with does not publish who you are)

## Context

A rented machine founds an identity as its own root and names an owner in that
inception. ADR-034 requires the machine to be told beforehand which identity may
claim it, so that an instance reachable on the public internet cannot be taken by
whoever arrives first. ADR-036 requires that identity to be **pairwise** —
derived for that one machine, meaningless anywhere else.

Both hold. The problem is that one identifier has been doing both jobs.

The claim proves *"I am the party this machine was reserved for."* The seal
records *"this identity is owned by."* Today the same value is used for each, so
the identity the infrastructure provider was told to expect becomes the identity
written into a public inception event, permanently.

## The problem

**The provider necessarily knows the claiming identity.** It was told that
identifier before the machine started — that is the whole of ADR-034, and it is
what stops a stranger taking the machine.

So when that identifier is also sealed as the owner, the provider can read the
published inception of any identity founded this way and recognise its own
customer. It does not need to attack anything. The correlation is published, by
us, in the one event that can never be rewritten.

That is the linkability ADR-036 exists to prevent, reintroduced one step later
and handed to the single party the sealed hardware exists to exclude.

**And the two identifiers have different lifetimes.** The claiming identity is
spent: it is minted so a machine can be reserved in its name, used once, and has
no purpose afterwards. The owner is permanent — it is who the founded identity
answers to for the rest of its existence, and an owner can only be named at
inception. Giving a permanent role to something designed to be ephemeral is how
the ephemeral thing ends up load-bearing.

## Decision

**The identity that claims a machine and the identity that owns what the machine
founds are different pairwise identities, and both are proved in the same
exchange.**

1. **The claim names the identity the machine was told to expect.** Unchanged
   from ADR-034: the machine compares it and refuses anything else.

2. **The founding names a separate owner.** It is supplied in the same request,
   and it is a different pairwise identity derived from the same seed — so it
   costs no extra backup and is recoverable from the recovery phrase alone.

3. **Both are proved, to the same standard.** The claimant demonstrates control
   of the claiming identity, as before. It must equally demonstrate control of
   the identity it is naming as owner — its key, its key event log, and a
   signature over the same challenge. **An owner sealed on an unproved assertion
   could be an identity that never agreed**, and an owner named at inception can
   never be replaced.

4. **Absent a separate owner, the claimant is the owner.** A computer somebody
   pairs from its own screen has one relationship and needs no second identity.
   The separation exists for the case where a third party learns the claimer.

## What this costs

**A second identity to derive, record and prove.** ADR-036 already requires the
derivation index of an owner identity to be stored at mint time, because an index
that is lost can never be re-derived — no rotation, no revocation, no recovery.
That now applies to two identifiers rather than one.

**A larger claim request.** The evidence bundle appears twice. That is the
honest price of two independent assertions; folding them into one is what created
this.

**Nothing changes for a machine you pair with directly.** No provider is told
anything, so there is nobody to correlate against, and the claimant remains the
owner.

## What this does not change

**The machine still founds its own root.** ADR-036 stands: no delegated
inception, nothing naming a parent in what the machine publishes.

**Owners are still named only at inception.** A later event may reorganise a set
of owners that exists; it may not conjure one where there was none. That is why
both identities have to be right the first time and why they are proved before
anything is minted.

## Consequences

An infrastructure provider learns which identity reserved a machine, and learns
nothing about what that machine went on to own. Two machines rented by one person
share no identifier an observer can join, and neither shares one with the identity
either machine founded.

A verifier resolving a founded identity sees an owner it can check signatures
against, and cannot tell from that identifier who rented the hardware or where.

The cost is borne once, at founding, by the party best placed to pay it: the
device holding the seed, which is deriving one identity already and can derive
two.
