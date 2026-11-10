# ADR-070 — Witness classes, and a receipt any KERI verifier can check

**Status:** Accepted. Supersedes three statements of ADR-016 (its "stub" status, its "max 3" cap, and its description of the receipt); the rest of ADR-016, including its endpoints and request workflow, stands. Corrects a statement in ADR-024.
**Date:** 2026-10-24 (decisions recorded from Rob Andersen, 2026-10-15)

This records decisions already made. It does not reopen them.

## Context

Three things were true at once and none was written down.

An Identity Agent can be a witness for another one, and a company can run witnessing as a service, but the code had only half-words for the difference (`Commercial` on a witness target, `BackendCommercial`, `witnessPathPrefix` choosing `/api` for peers). Nothing named the two kinds, so nothing could say which one a person was relying on.

ADR-031 says bootstrap witnesses are "appended, never preferred", but not why. The reason is the point of the design and was left implied.

The receipt a witness issues was not a KERI receipt. keripy's `eventing.receipt` has five fields, `v` `t` `d` `i` `s`. Ours had seven: `v` was the bare string `KERI10JSON` (not a parseable version string, which carries a size and a trailing underscore), `i` held the **witness** where KERI puts the **controller**, `s` was missing in favour of an integer `seq`, and `aid` and `dt` were extras. The signature was over the 44-character SAID string where keripy's `Hab.witness` signs the serialised event, and it was an unindexed `0B` signature where keripy attaches an indexed one under a witness-signature counter. A receipt in that form means something to our code and nothing to anybody else's.

## Decision

### Two classes of witness (and watcher), named everywhere

- **Peer** (peer witness, peer watcher): another Identity Agent, individual or organisation, acting for a contact. It must be witness-worthy, meaning always on; `IsBackendEligible` in `identity-agent-core/witness/eligibility.go` already enforces that by excluding mobile.
- **Commercial**: a Service Provider running the service as a product.

The class is used in code, on the wire and in the interface, and is the thing a person is told when they are told who their witnesses are.

### The peer cluster is the point

Rob: *"ideally we want people to use their own cluster of witnesses (other identity agents that also serve as witnesses) because it removes centralized dependence on large witness service providers."*

Commercial witnesses exist for **continuity**: confidence when a person deals with people new to their network, who have no peers yet. They are explicitly **not** architecturally required for a mature Identity Agent with many contacts. That is ADR-031's "appended, never preferred" with its reason stated: a person leans on their own peers first, and a commercial witness is a dependency to be grown out of, not one to be built on. ADR-031 also gives a lasting reason to keep a commercial witness: on a pairwise AID the peer list is what leaks, so it takes commercial witnesses only, permanently. (ADR-031's pairwise exception stands: a pairwise AID takes commercial witnesses only, permanently, because on a pairwise AID the peer list is what leaks.)

### Where conformance binds

Conformance means speaking KERI's wire form well enough that software written against the KERI specification, by someone who knows nothing about us, interoperates. It binds at two layers, differently.

**Artifact layer: conforms everywhere, peer and commercial alike.** The receipt itself:

- a valid `rct`: `v` is `KERI10JSON{size:06x}_`, `t` is `rct`, `d` is the receipted event's SAID, `i` is the **controller's** prefix, `s` is lowercase hex without leading zeros, and nothing else;
- signed over the **serialised event bytes**;
- with an **indexed** signature (code `A`), the index being the witness's position in the controller's witness list, as `Hab.witness` does it.

This is not negotiable, because it is what makes a receipt mean anything to anyone outside.

**Transport layer: may differ.** The route and envelope. Peers keep the optimised path (`/api/witness/*`, JSON envelope). The outside world gets keripy's (`POST /receipts`, `application/cesr+json`, signatures in `CESR-ATTACHMENT` headers).

**Why this split.** It gives **one receipt format and two thin transports**, not two receipt formats joined by a semantic adapter. An adapter translates between two things that mean subtly different things, and that is where trust gaps and bugs live. A transport shim is routing and framing only. It keeps what Rob asked for, which is simplicity, no adapters, and an optimised internal architecture where an Identity Agent can be simpler than KERI has to be, while every receipt an Identity Agent produces is verifiable by any KERI verifier.

The keripy-style transport for the outside world is **not built by this ADR**; it is the transport half of this decision and is a separate piece of work. The envelope the agents use today carries the same receipt.

### Both directions must work

An Identity Agent consumes witness services and provides them. It must be able to (a) designate and use a third-party KERI witness such as KERI Health as a commercial witness, and (b) serve as a witness to other agents. Rob: *"anyone should be able to be used as long as it is KERI protocol."* A witness is therefore chosen by whether it speaks KERI, not by who runs it.

### Default pool size

Ship with one commercial provider; expand to three if the user base warrants; seven is the ceiling because net return beyond that is marginal. **Plurality of operator, not merely of instance**, is the maturity goal: at saturation, witnesses and watchers are different operators and different classes. The principles are firm (user control, executable governance, decentralisation, maximum Identity Agent control) and the end state is not instantly attainable.

### Honesty

The product always states plainly what protection the user actually has. Three AIDs under one operator is plurality of instance and is never presented as plurality of operator.

### Three different sevens

"One, then maybe three, at most seven" was said about **default commercial witness providers shipped in the registry**, and about nothing else. It does not change either number in `identity-agent-core/witness/types.go`: `MaxWitnessSetSize = 9` caps an identity's total designated witness set including peers, and `TargetContactWitnesses = 7` is how many contact witnesses an agent aims to enrol. ADR-024's "max 9, target 7, default threshold 5" describes those, not the provider count. Nothing here lowers `MaxWitnessSetSize`. Whether the provider ceiling and the set cap should be related is a separate decision nobody has made.

## The signing payload

Until this change a receipt was a signature over the SAID string, with a comment on `signWitnessReceipt` calling it a deviation from the wire form an external witness uses. That was the only place it was admitted. It is recorded here: **the deviation existed, and it is removed.**

The reasoning for the old scheme was sound as far as it went: an event's SAID is a digest of the event, so signing the digest commits to the event, and it does not depend on two sides reproducing an identical serialisation. It was not cryptographically wrong. It was private: no one who did not write our code could verify it. The serialised bytes are what a SAID is a digest of, are what the controller's own signature is over, and are what every keripy verifier checks, so they are what is signed now.

## Migration

Receipts already stored were signed under the old rule and verify under the old rule. The decision, given the product is pre-release:

- **Writers emit only the current form.** The Go agent's `ReceiveSignedEvent` issues the five-field `rct` and an indexed signature over the event bytes. Nothing issues the old form again.
- **Readers accept both, told apart by the signature itself** (an indexed `A` signature is the current form, an unindexed `0B` is the old one), so no stored receipt is re-issued or re-signed and a witness that has not been upgraded keeps working. The old form is verified exactly as before, over the SAID string.
- **The old reader is removed** once no witness in service still sends it. It is not kept as a permanent second format. Removing it is tracked as the end of this migration.
- **Order of deployment: readers first.** An agent that has not yet got this change cannot verify a current-form receipt. That is accepted before release, and the order to follow after it is to upgrade agents, then the hosted witness service.
- **Other implementations of a witness** must adopt the same form. Until one does, it keeps writing the old form, which readers accept, and receipts our agent issues are not checked by it.

A current-form receipt has to be checked against the event it signed, so a receipt is stored alongside nothing but its signature and is verified wherever the event is at hand: when counting receipts against a key log, when a bundle is verified, and when a receipt is first saved with its event. Read back with no event, a stored receipt is checked only for being a well-formed indexed signature by a witness that is its own key.

## Claims this retires

Each answers four questions: what sentence is now false, what is true instead, where it was decided, and where the old wording is still legitimately allowed.

1. **"The witness protocol is a stub; full implementation deferred to Sprint 4"** (ADR-016 status). False: enrolment, requests, receipts, finalisation and withdrawal are built. True instead: ADR-016's endpoints and request workflow are the protocol and stand, as amended by its own dated amendments and, for the receipt, this ADR; only the stub status, the "max 3" cap and the receipt description are superseded. Decided here. Allowed still: ADR-016's own history.
2. **"Max 3 witnesses concurrently"** (ADR-016, behaviour of `/api/witness/request`). False: the code's cap on identities one agent witnesses for is `MaxOutgoingWitnessing = 15`. True instead: 15, and an identity's own witness set is capped at `MaxWitnessSetSize = 9`. Decided here, from the code. Allowed still: nowhere.
3. **"The service returns a CESR receipt"** (ADR-024, witness service). False: it returned a JSON object that was not a KERI receipt. True instead: it returns the five-field `rct` and an indexed signature over the event bytes, in the agents' JSON envelope; the CESR transport is separate and not yet built. Decided here. Allowed still: the description of the keripy transport as the outside-world route.
4. **"A receipt is `v: KERI10JSON`, `i` the witness, `seq`, `aid`, `dt`, signed over the SAID"** (code comments, ADR-016 text, `receiptFromResponse` callers). False: not parseable as KERI. True instead: the five-field `rct`, `i` the controller, signed over the event bytes with an indexed signature. Decided here. Allowed still: the migration reader's comments, and this ADR.

## Corrections made in this change

- ADR-016's status line says which three statements this ADR supersedes, and its "max 3" is corrected to the code's value.
- ADR-024's "returns a CESR receipt" is corrected to say what it returns.

## Consequences

- A receipt one of our witnesses issues is accepted by keripy's own parser and verified against the controller's key log. `identity-agent-core/interop/verify_witness_receipts_with_keripy.py` is the check, and its test vectors are made by keripy itself (`make_witness_receipt_vectors.py`, `drivers/testdata/keripy_witness_receipts.json`).
- `witnessingReport` can now reject a receipt whose index is not the witness's place in the designated list.
- The class names exist in this ADR. Making the class names visible in the registry, on the wire and in the interface is follow-on work.
