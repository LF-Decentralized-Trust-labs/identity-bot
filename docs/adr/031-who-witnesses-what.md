# ADR-031 — Who witnesses what

**Status:** Accepted
**Date:** 2026-07-29

## Context

Witnesses observe an identity's key events and issue receipts. Their value is
duplicity detection: an identity whose events nobody receipts can present two
different histories to two different people, and nothing in the protocol notices.

Witnessing here is peer-to-peer by design. Every Identity Agent witnesses its
contacts, so most people's witnesses are people they already know — no third
party, no cost, and no operator whose business the network depends on.

Two problems sat underneath that design.

**A new identity has no contacts.** The gap is one of ordering rather than
principle: the moment an identity is most worth witnessing — inception, when its
keys are established and the log's first entry is written — is the moment it has
the fewest people to ask.

**A pairwise AID cannot use contacts at all.** A separate AID per relationship
exists so that two counterparties cannot tell they are dealing with the same
person. But **witness lists are public** — the witness set is named in the
inception event itself. So the set is an identifier in its own right. Two
pairwise AIDs naming the same distinctive handful of friends are trivially
linkable to one person. Separate keys and separate relay URLs buy nothing if the
witness list rejoins them.

The eligibility rule already refused contact witnesses on pairwise AIDs, which is
correct. But on a fresh identity it refused *everything*, because no commercial
witness was enrolled as a contact yet. The result was that the AIDs used for real
relationships — the ones that actually matter — had no witnesses at all.

## Decision

**A small bootstrap pool covers a new identity until it has contacts of its own.**
Bootstrap witnesses are appended, never preferred: an identity with enough
contacts leans on those, and the bootstrap contribution shrinks to nothing on its
own as contacts accumulate. A contact who happens to also be in the pool is
counted once, not twice — counting it twice would inflate the threshold while
adding no independent observer, which is worse than a smaller honest pool because
it looks stronger than it is.

**A pairwise AID takes commercial witnesses only, permanently.** A commercially
operated witness serves a large population, so naming one says almost nothing
about who you are — a large anonymity set rather than a fingerprint.

**A pairwise AID with no commercial contacts takes exactly one bootstrap witness.**
One rather than several: it needs an observer that will notice duplicity, not a
quorum. Each additional witness is more correlation surface bought for
availability that a single relationship does not need.

**Which one is chosen by hashing the AID.** Sending all of somebody's pairwise
AIDs to one operator would hand that operator the contact graph in its own logs.
Spreading the choice across the pool by AID keeps it stable for any given AID — so
an event always goes to the same place and a receipt can be chased — while no
single operator sees more than its share. The hash is a bucketing function, not a
security property, and does not pretend otherwise.

## The part that inverts

Everywhere else, the intent is that a person's own contacts **displace**
commercial witnesses as they accumulate. Peer witnessing is the design; depending
on somebody's business is the thing being grown out of.

On a pairwise AID that instinct is exactly wrong, because there the contacts are
what leaks. Peers never displace commercial witnesses on a pairwise AID, however
many of them there are. This is the single place the two principles conflict, and
privacy wins, because peer witnesses are the thing that breaks unlinkability.

A test states this outright rather than leaving it to a comment, so that relaxing
it has to be a deliberate act.

## Consequences

- A new identity is witnessed from inception rather than from whenever it happens
  to acquire contacts.
- Pairwise AIDs get duplicity detection they previously did not have.
- The bootstrap pool's operators see the pairwise AIDs routed to them. This is
  the residual cost, reduced but not eliminated by spreading across the pool; it
  is accepted because the alternative — contact witnesses — is a worse leak, and
  the further alternative of no witness is no detection at all.
- A witness set is written into a signed inception event and is therefore
  permanent for that AID. Changing this policy later does not change AIDs already
  incepted under it, which is why it is settled now rather than deferred.
- There is a lasting reason to keep a commercial witness even after contacts are
  plentiful, and it is not availability. A professionally operated witness is
  systematically run, which makes it badly placed to do any one person a favour:
  bending the rules would mean changing a process and staking a business on it. A
  friend's agent offers a different assurance, held for different reasons. Both
  together are worth more than either alone.

## Alternatives considered

**Contact witnesses on pairwise AIDs.** Free, scales with the network, and needs
no operator. Rejected: the witness set is public, so a distinctive contact set is
a fingerprint that links otherwise-unlinkable AIDs. This is a break rather than a
trade-off.

**Three bootstrap witnesses on pairwise AIDs, matching root.** Better
availability. Rejected: triples the correlation surface to buy redundancy a single
relationship does not need.

**One fixed bootstrap witness for all pairwise AIDs.** Simpler and needs no hash.
Rejected: that operator could reassemble the contact graph from its own logs.

**No witnesses on pairwise AIDs at all.** Maximum privacy. Rejected: it leaves the
AIDs used for real relationships with no duplicity detection, which is the failure
witnessing exists to prevent.
