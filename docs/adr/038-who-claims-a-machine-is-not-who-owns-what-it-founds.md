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

## Amendment 1 (2026-11-19): what each party signs when a separate owner is named, and who confirms the owner's history

**Status:** Accepted. **Amends:** Decision item 3 of this ADR. **Relates to:** ADR-034 (an
instance is told who may claim it), ADR-016 (the witness protocol).

### What changes

Decision item 3 asked the owner for "a signature over the same challenge" and did not say what the
bytes are. It now does, and the claim signs for the owner it names. The owner's key log is put to
its witnesses as the claimant's is. With that, "to the same standard" in item 3 is true.

### What is signed

Each input is a JSON object of strings with its keys in sorted order and no whitespace, signed as
UTF-8 by the key the signer's own key log puts in force. `challenge` and `machine_public_key` are
what the machine offered, and `claim_token` is the code the claim presents.

String values are escaped as JSON requires, and five characters are written as escapes as well:
`<`, `>` and `&` as `\u003c`, `\u003e` and `\u0026`, and U+2028 and U+2029 as `\u2028` and `\u2029`.
Identifiers, keys and the challenge never hold any of these. A `claim_token` is chosen by whoever
set the machine up and may, so an implementation that signs or checks these inputs escapes them
the same way.

**A claim that names no separate owner signs what it always did.** These bytes do not change:

```
{"challenge":"…","claim_token":"…","machine_public_key":"…","owner_aid":"<claimer>"}
```

**A claim that names a separate owner signs for that owner.** The claimer signs:

```
{"challenge":"…","claim_token":"…","founded_owner_aid":"<owner>","machine_public_key":"…","owner_aid":"<claimer>"}
```

**The owner signs as an owner, for that claimer.** The owner signs:

```
{"challenge":"…","claim_token":"…","claimer_aid":"<claimer>","founded_owner_aid":"<owner>","machine_public_key":"…","role":"founded_owner"}
```

Why it matters: the owner decides the outcome as much as the machine's key does. A claim that did
not sign for its owner could have the owner replaced on the way, or removed so that the claiming
identity is sealed as owner after all. An owner that signed only the exchange would have agreed to
be named by whoever presented its signature. The three inputs have different keys, so a signature
over one is never a signature over another.

### What a machine refuses

A request that names a separate owner is refused, before anything is founded, unless it carries the
owner's key, its key log and its signature. The key must be the one the log puts in force.

### Who confirms the owner's history

A key log shows nothing of an event withheld from it, so a key an identity has rotated away from
still signs correctly against the log as it stood before. The owner's log is therefore put to the
witnesses it designates, by the one check the claimant's is put to: a history a witness contradicts,
or one that cannot be checked, is refused on every machine, and a history nobody confirms is refused
on a machine that was told whom to expect by whoever set it up. A computer paired from its own
screen may have no network, so there an unconfirmed history is accepted and recorded, for the owner
as for the claimant.
