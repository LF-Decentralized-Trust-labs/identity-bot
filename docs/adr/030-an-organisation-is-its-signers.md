# ADR-030: An Organisation Is Its Signers

**Status:** Accepted
**Date:** 2026-07-29

## Context

An organisation's agent created its own identity, and whoever redeemed a one-time invitation was written into a table as `Super Admin` with a signature filed beside it as evidence.

Nothing consulted that evidence before acting. The owner-authority lookup falls back to *"this agent's own identity is the authority"* when no record is sealed, so the organisation owned itself. On rented hardware that means the box holds the only key that matters and nobody outside it can prove otherwise.

The fallback is why this was invisible rather than broken. Everything kept working — it was simply signed by the wrong party.

Separately, multi-signature inception passed `ndigs=[]`, committing to no successor keys. An identity created that way **can never be rotated**: a signer whose key is compromised could never be replaced, and transferring ownership is itself a rotation.

## Decision

**An organisation's identity is a multi-signature identity whose keys are its owners.** Not a record listing who owns it — the keys themselves.

That makes the properties structural rather than enforced by a handler:

- It cannot exist until the signers sign, because the inception event *is* the signing. Before threshold there is no AID, not a pending flag.
- It cannot act without the threshold, because that is what a multi-signature identity is.

The founding ceremony seals the signer as the agent's owner authority, **before** the roster is written. Ordering is the design: roster-first would mean a failed seal leaves an organisation that looks founded — an active administrator on the list — while still answering to nobody. Sealing first means a failure leaves it unfounded, which can be done again.

A signer with no public key is refused rather than recorded, since an organisation whose owner cannot be verified is the condition the ceremony exists to prevent.

Multi-signature inception now carries next-key digests, so the identity can rotate.

Two consequences worth stating explicitly, because they are not obvious:

**Signers sign once, not continually.** They bring an operating identity into being; that identity hires, scopes and revokes. Signers are needed again only for things that change the organisation itself — adding or removing a signer, changing the threshold, rotating the root, revoking the operating identity. Otherwise five owners would have to sign to onboard a receptionist.

**Employees are credentials, not delegations.** A delegation is anchored in the delegator's log, so employees-as-delegates would make every hire a threshold-signed event, published in the organisation's public log, growing with headcount forever. Credentials issue from the operating identity's registry instead.

## Consequences

**Good.** The organisation stops owning itself. A two-owner company cannot act without both, and cannot be founded by one. Ownership becomes checkable by anyone rather than asserted by a table.

**Costly.** Founding now requires collecting signatures from every designated signer, which is a multi-party ceremony rather than one HTTP call. An organisation whose signers cannot assemble cannot be founded — correctly, but it is a real constraint.

**Accepted risk.** An `n`-of-`n` threshold means losing any one key ends the organisation's ability to act. This is why the recovery phrase is treated as one key in the signer set rather than a separate mechanism: with two or more owners it works only alongside one of them, so a found printout is not the company, and its presence turns 2-of-2 into 2-of-3.

## Alternatives Considered

**Keep the roster and check it before acting.** Rejected: it makes ownership a thing the software chooses to honour rather than a thing the identity *is*. The fallback that caused this bug would still exist, one layer up.

**Delegation for organisations that own organisations.** Rejected. A delegation cannot be transferred, only destroyed — so a delegated subsidiary could not be sold without killing its identity and everything it ever signed. Separate inception with the parent as a signer makes a sale a key rotation, and the company survives its owner.

**Weighted thresholds at founding.** Deferred, not rejected. Founding is unanimous regardless; the ongoing threshold is configurable, and weighted forms are a later refinement.
