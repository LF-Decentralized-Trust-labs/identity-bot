# ADR-078: The Measurement List Is Issued Under a Publisher Identity and Anchored in Its Witnessed Key History

**Status:** Proposed (2026-11-12)
**Date:** 2026-11-12
**Deciders:** to be decided; no released version holds a list
**Builds on:** ADR-076 (the list is the policy; the owner may add to it once), ADR-075 (duplicity), ADR-035 (what a verifier checks for itself)
**Supersedes in part:** ADR-076's statement that the list is signed by a publisher key pinned in the build. Its decisions 1 to 7 stand.

---

## Context

ADR-076 takes the list of accepted launch measurements from a document signed with one Ed25519 key whose public half is pinned in each build. That key cannot be rotated without shipping new builds, cannot be shared among several people, and leaves no public record of what was ever issued, so a list that was withdrawn cannot be told apart from one that was never shown. The publisher already is an identity: a key history that is witnessed and that anyone can read.

## Decision

1. **A list is a credential issued by the publisher identity.** It is an ACDC whose attribute block carries the list's content (`sequence`, `published_at`, `expires_at`, `images`, with the entry rules of ADR-076's list unchanged) and no holder, issued into a backerless registry (`vcp` with the configuration trait `NB`, `bt` "0", no backers). A withdrawn list has a revocation (`rev`) naming its issuance (`iss`).
2. **Each registry event is sealed in the publisher's key history** by an event seal `{i, s, d}` in an interaction event: `i` the credential's identifier (the registry's, for its inception), `s` the event's sequence number in lowercase hex, `d` its SAID. The key history is signed at the threshold in force and receipted by the identity's witnesses.
3. **A build pins the publisher's identifier, its inception event, its registry's identifier and the schema's SAID, and no key.** Keys come from the key history, so the publisher may rotate, or move from one key to several, with no new build. The checker takes every threshold from the log.
4. **A list is accepted only if** (`identity-agent-core/measurementlist/anchored`, `Verify`):
   - at least the witness threshold of the publisher's designated witnesses signed a tip in answer to a nonce this device sent, and all name one tip. The bundle's history ends at that tip, so a withdrawal reaches every decision as soon as it is witnessed, without trusting a clock;
   - the history's inception is the pinned one, `ValidateSignedKEL` passes (signing threshold, and a rotation meeting its prior next threshold by the keys it presents), every event has its threshold of receipts, and the history extends the one this device already holds, else it is duplicity;
   - every event seal is matched by a registry event the bundle holds and every registry event is sealed, so a withdrawal that is withheld is seen from its seal alone;
   - the credential is the pinned publisher's, under the pinned schema, in the pinned registry, and names no holder;
   - it is the newest issued and not withdrawn;
   - every rule ADR-076 states for a signed list holds (`measurementlist.FromContent`: sequence floor, same sequence with other content, expiry, entry windows and shape).
5. **The check is pure, and the question is asked inside it.** The time and the witnesses' answers are inputs, and a caller cannot skip the freshness input. `VerifyAsking` takes a function that asks the witnesses, and calls it only once the history is known to be genuine, with the witnesses that history designates, so a question cannot go to witnesses the history does not name. `anchored.Resolver` is that function over `witness.Service.AskTips`: a new random nonce for each witness for each question, kept nowhere and used once.
6. **The bundle** is `{bundle_version: 1, publisher, registry, kel, tel, credentials}`, at most 4 MiB, with no signature of its own: every part is checked and nothing is trusted for being there.
7. **Anchors other than registry event seals** (the owner named at founding, a handover's steps) are the identity's own and are not read.

8. **The core takes the list on one route and decides from what it checked.** `POST /api/measurement-list` takes a candidate bundle, asks the witnesses, checks it against the pin and the floors, and only then stages it. A staged list is the policy for one hour after the witnesses were asked and while its own dates hold, is kept in memory only (after a restart it must be checked again), and once any list has been accepted the bootstrap is never used again. Nothing is read from a file or the environment, and a conflicting history is kept as evidence (`measurement_publisher_duplicity.json`).

## Consequences

- The publisher can be a single key held by one box, and later several keys, with the same checker and the same pin.
- `PinnedKeyID` and `PinnedKeyHex` are gone, replaced by the pin of decision 3; a build without a pin accepts no list. The signed-document reader in `measurementlist` (`Verify`) has no caller in the core and goes with the Dart verifier.
- An anchored list may say `list_version` 2 in its attribute block, and its entries then carry `environment`, `svn`, `smt` and `retired`, read by the same code as a signed list's.
- ADR-076 decision 7 stands and applies to whatever issues a list: the issuing tool refuses an entry marked as development.
- The floors (the highest list sequence and its hash, and the newest place of the publisher's history this device has held) never fall below the build's bundled snapshot.
- Tests: `identity-agent-core/measurementlist/anchored` (`verify_test.go`, one negative case per refusal; `engine_test.go`, the engine's own output end to end).

## Superseded wording

"The list is Ed25519-signed by a publisher key pinned in the build" is false from this decision on. True instead: the list is issued under a pinned publisher identity and anchored in its witnessed key history. The old wording is allowed in ADR-076's own history.
