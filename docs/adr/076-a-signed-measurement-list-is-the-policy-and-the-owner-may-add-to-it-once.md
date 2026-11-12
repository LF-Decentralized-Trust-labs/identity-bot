# ADR-076: A Signed Measurement List Is the Policy, and the Owner May Add to It for One Adoption

**Status:** Proposed (2026-11-12)
**Date:** 2026-11-12
**Deciders:** to be decided; the list is built, no released version depends on it
**Builds on:** ADR-035 (what a verifier can check for itself: which measurement to accept is the reader's policy)

---

## Context

A launch measurement says what a machine booted. Whether that is software an owner accepts is the owner's policy, and it cannot come from the machine being checked. The core takes that policy from a signed list of measurements (`identity-agent-core/measurementlist`, checked against a publisher key pinned in the build), with `AGENT_ACCEPTED_MEASUREMENTS` as a bootstrap for before any list exists.

`POST /api/pairing/adopt` also accepts `accepted_measurements`: values the owner names for that one adoption. The question is whether that survives once a list has been accepted.

## Decision

1. **A verified list is the whole standing policy.** Nothing is added to it from the environment.
2. **Once a list has been accepted here, the bootstrap is never used again.** A corrupted, missing, older, expired or wrong-key list means no box is accepted, and the refusal says why.
3. **The owner's `accepted_measurements` on an adoption request is kept, after a list has been accepted too.** It is the owner's own statement on an owner-only route, not something a box, a browser or the list's publisher can supply.
4. **It can only add, and only what the owner named.** The adoption test is "the standing policy, or exactly these values" (`acceptableOrOwnerNamed` in `identity-agent-core/server/measurement_policy.go`). It is not stored and changes no policy for any other request. When the list is refused, the policy is empty, so only the named values are accepted; the bootstrap, the older list's entries and every other value stay refused. It does not make a measurement trustworthy; it records that the owner chose it.

5. **The core decides; an app only supplies the list.** An app that launches or embeds a core gives it the signed list itself, as the file named by `AGENT_MEASUREMENT_LIST_FILE` or, when that is unset, `measurement_list.json` in the data directory (`measurementListPath` in `identity-agent-core/server/measurement_policy.go`). The core checks it against the pinned key, its recorded floor, the expiry and each entry's window on every decision. An app does not send the measurements from a list it checked itself as `accepted_measurements`: that would bypass the floor, expiry and retirement and leave security as weak as the weaker of the two verifiers. `accepted_measurements` stays for an explicit owner action only (an image they built themselves), shown to them as such. An app's own check of the list (`agent_client`'s `measurement_list.dart`) serves to avoid replacing a good staged list with a bad one and to show a person what would be accepted; it holds no floor of its own.
6. **The same sequence with different content is refused.** Once the list at a sequence is recorded, another list at that sequence is `ErrConflictingList` in Go and Dart (vector `same_sequence_different_content.json`).

## Consequences

- An owner who builds their own image can adopt it without waiting for the publisher's list, at the cost of vouching for it themselves. That is the owner's right over their own machine.
- The rollback protection binds everyone except the owner acting knowingly. Anyone who can call the owner-only route can already adopt any machine they like, so this adds no reach.
- Test: `TestTheOwnersNamedMeasurementOnlyAddsAndNeverLiftsAListRefusal` (`identity-agent-core/server/a_verified_measurement_list_replaces_the_bootstrap_test.go`).
