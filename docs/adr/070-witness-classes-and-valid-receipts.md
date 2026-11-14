# ADR-070 — Witness classes, and a receipt any KERI verifier can check

**Status:** Accepted. Supersedes three statements of ADR-016 (its "stub" status, its "max 3" cap, and its description of the receipt); the rest of ADR-016, including its endpoints and request workflow, stands. Corrects a statement in ADR-024.
**Date:** 2026-10-24

## Context

Two things were true at once and neither was written down.

An Identity Agent can be a witness for another one, and a company can run witnessing as a service, but the code had only half-words for the difference (`Commercial` on a witness target, `BackendCommercial`, `witnessPathPrefix` choosing `/api` for peers). Nothing named the two kinds, so nothing could say which one a person was relying on.

The receipt a witness issues was not a KERI receipt. keripy's `eventing.receipt` has five fields, `v` `t` `d` `i` `s`. Ours had seven: `v` was the bare string `KERI10JSON` (not a parseable version string, which carries a size and a trailing underscore), `i` held the **witness** where KERI puts the **controller**, `s` was missing in favour of an integer `seq`, and `aid` and `dt` were extras. The signature was over the 44-character SAID string where keripy's `Hab.witness` signs the serialised event, and it was an unindexed `0B` signature where keripy attaches an indexed one under a witness-signature counter. A receipt in that form means something to our code and nothing to anybody else's.

## Decision

### Two classes of witness (and watcher), named everywhere

- **Peer** (peer witness, peer watcher): another Identity Agent, individual or organisation, acting for a contact. It must be witness-worthy, meaning always on; `IsBackendEligible` in `identity-agent-core/witness/eligibility.go` already enforces that by excluding mobile.
- **Commercial**: a Service Provider running the service as a product.

The class is used in code and carried on the wire as `WitnessEntry.Class`.

### Where conformance binds

Conformance means speaking KERI's wire form well enough that software written against the KERI specification, by someone who knows nothing about us, interoperates. It binds at two layers, differently.

**Artifact layer: conforms everywhere, peer and commercial alike.** The receipt itself:

- a valid `rct`: `v` is `KERI10JSON{size:06x}_`, `t` is `rct`, `d` is the receipted event's SAID, `i` is the **controller's** prefix, `s` is lowercase hex without leading zeros, and nothing else;
- signed over the **serialised event bytes**;
- with an **indexed** signature (code `A`), the index being the witness's position in the controller's witness list, as `Hab.witness` does it.

This is not negotiable, because it is what makes a receipt mean anything to anyone outside.

**Transport layer: may differ.** The route and envelope. Peers keep the optimised path (`/api/witness/*`, JSON envelope). The outside world gets keripy's (`POST /receipts`, `application/cesr+json`, signatures in `CESR-ATTACHMENT` headers).

**Why this split.** It gives one receipt format and two thin transports, not two formats joined by a semantic adapter, which is where trust gaps live. A transport shim is routing and framing only, and every receipt an Identity Agent produces is verifiable by any KERI verifier.

The keripy-style transport for the outside world is **not built by this ADR**; it is the transport half of this decision and is a separate piece of work. The envelope the agents use today carries the same receipt.

### Both directions must work

An Identity Agent consumes witness services and provides them. It must be able to (a) designate and use a third-party KERI witness such as KERI Health as a commercial witness, and (b) serve as a witness to other agents. Any witness that speaks the KERI protocol can be used. A witness is therefore chosen by whether it speaks KERI, not by who runs it.

## The signing payload

A receipt signs the serialised event bytes. The earlier scheme signed the event's SAID string, which commits to the event but cannot be checked by anyone who did not write our code. The serialised bytes are what a SAID is a digest of, are what the controller's own signature is over, and are what every keripy verifier checks, so they are what is signed now.

## Migration

Receipts already stored were signed under the old rule and verify under the old rule. Stored receipts are read as follows:

- **Writers emit only the current form.** The Go agent's `ReceiveSignedEvent` issues the five-field `rct` and an indexed signature over the event bytes. Nothing issues the old form again.
- **Readers accept both, told apart by the signature itself** (an indexed `A` signature is the current form, an unindexed `0B` is the old one), so no stored receipt is re-issued or re-signed and a witness that still sends the old form keeps working. The old form is verified exactly as before, over the SAID string.
- **The old reader is removed** once no witness in service still sends the old form. It is not kept as a permanent second format.
- **Other implementations of a witness** must adopt the same form. Until one does, it keeps writing the old form, which readers accept, and receipts our agent issues are not checked by it.

A current-form receipt has to be checked against the event it signed, so a receipt is stored alongside nothing but its signature and is verified wherever the event is at hand: when counting receipts against a key log, when a bundle is verified, and when a receipt is first saved with its event. Read back with no event, a stored receipt is checked only for being a well-formed indexed signature by a witness that is its own key.

## Claims this retires

Each says what is now false, what is true instead, where that was decided, and where the old wording is still allowed. ADR-016's status line and ADR-024's description of the receipt are corrected to match.

1. **"The witness protocol is a stub; full implementation deferred to Sprint 4"** (ADR-016 status). False: enrolment, requests, receipts, finalisation and withdrawal are built. True instead: ADR-016's endpoints and request workflow are the protocol and stand, as amended by its own dated amendments and, for the receipt, this ADR; only the stub status, the "max 3" cap and the receipt description are superseded. Decided here. Allowed still: ADR-016's own history.
2. **"Max 3 witnesses concurrently"** (ADR-016, behaviour of `/api/witness/request`). False: the code's cap on identities one agent witnesses for is `MaxOutgoingWitnessing = 15`. True instead: 15, and an identity's own witness set is capped at `MaxWitnessSetSize = 9`. Decided here, from the code. Allowed still: nowhere.
3. **"The service returns a CESR receipt"** (ADR-024, witness service). False: it returned a JSON object that was not a KERI receipt. True instead: it returns the five-field `rct` and an indexed signature over the event bytes, in the agents' JSON envelope; the CESR transport is separate and not yet built. Decided here. Allowed still: the description of the keripy transport as the outside-world route.
4. **"A receipt is `v: KERI10JSON`, `i` the witness, `seq`, `aid`, `dt`, signed over the SAID"** (code comments, ADR-016 text, `receiptFromResponse` callers). False: not parseable as KERI. True instead: the five-field `rct`, `i` the controller, signed over the event bytes with an indexed signature. Decided here. Allowed still: the migration reader's comments, and this ADR.

## Consequences

- A receipt one of our witnesses issues is accepted by keripy's own parser and verified against the controller's key log. `identity-agent-core/interop/verify_witness_receipts_with_keripy.py` is the check, and its test vectors are made by keripy itself (`make_witness_receipt_vectors.py`, `witnessproto/testdata/keripy_witness_receipts.json`).
- `witnessingReport` can now reject a receipt whose index is not the witness's place in the designated list.
- The class is carried on the wire as `WitnessEntry.Class` (`identity-agent-core/witness/types.go`).
