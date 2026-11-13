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
3. **A build pins the publisher's identifier, its inception event and its registry's identifier, and no key.** The schema is not set at build time: it is a committed document (`identity-agent-core/measurementlist/anchored/schema/accepted-launch-measurements.json`, a JSON Schema whose `$id` is its own SAID) and its SAID is derived from it, so no build can name another. The list's content is held to the rules of `measurementlist.ContentOfAttributes` and `FromContent`, and `testdata/schema_conformance.json` is the shared vectors (accepted and refused attribute blocks, and one whole credential under the schema) that another implementation holds its reading to. Keys come from the key history, so the publisher may rotate, or move from one key to several, with no new build. The checker takes every threshold from the log.
4. **A list is accepted only if** (`identity-agent-core/measurementlist/anchored`, `Verify`):
   - at least the witness threshold of the publisher's designated witnesses signed a tip in answer to a nonce this device sent, and all name one tip. The bundle's history ends at that tip, so a withdrawal reaches every decision as soon as it is witnessed, without trusting a clock;
   - the history's inception is the pinned one, `ValidateSignedKEL` passes (signing threshold, and a rotation meeting its prior next threshold by the keys it presents), every event has its threshold of receipts, and the history extends the one this device already holds, else it is duplicity;
   - every event seal is matched by a registry event the bundle holds and every registry event is sealed, so a withdrawal that is withheld is seen from its seal alone;
   - the credential is the pinned publisher's, under the pinned schema, in the pinned registry, and names no holder;
   - it is the newest issued and not withdrawn;
   - every rule ADR-076 states for a signed list holds (`measurementlist.FromContent`: sequence floor, same sequence with other content, expiry, entry windows and shape).
   - "now" for every date above is never earlier than the newest `published_at` this device has accepted. A sealed box's clock is its host's to set, and a host that sets it back must not revive an expired list or reopen a window the box has seen close. The floors keep that date with the others.
5. **The check is pure, and the question is asked inside it.** The time and the witnesses' answers are inputs, and a caller cannot skip the freshness input. `VerifyAsking` takes a function that asks the witnesses, and calls it only once the history is known to be genuine, with the witnesses that history designates, so a question cannot go to witnesses the history does not name. `anchored.Resolver` is that function over `witness.Service.AskTips`: a new random nonce for each witness for each question, kept nowhere and used once.
6. **The bundle** is `{bundle_version: 1, publisher, registry, kel, tel, credentials}`, at most 4 MiB, with no signature of its own: every part is checked and nothing is trusted for being there.
7. **Anchors other than registry event seals** (the owner named at founding, a handover's steps) are the identity's own and are not read.

8. **The core takes the list on one route and decides from what it checked.** `POST /api/measurement-list` takes a candidate bundle, asks the witnesses, checks it against the pin and the floors, and only then stages it. A staged list is the policy for one hour after the witnesses were asked and while its own dates hold, is kept in memory only (after a restart it must be checked again), and once any list has been accepted the bootstrap is never used again. Nothing is read from a file or the environment, and a conflicting history is kept as evidence (`measurement_publisher_duplicity.json`).

9. **The person's peer watchers are asked too.** `Resolver` asks the witnesses the bundle's history names, and those alone, so a device whose floor predates a rotation that replaced every witness can be served a stale bundle (a list that has since been withdrawn) and have it vouched for by witnesses whose keys are retired. **This is a limit of KERI and no check of the bundle can remove it.** What reduces it is a second source: the core also asks the contacts the owner chose (`watcher.Service.AskPeerTips`, `POST /public/kel-tip`, signed to each peer as a cross-check is), and a peer that holds more of the publisher's history than the bundle, or another event at a place the bundle holds, refuses the bundle (`anchored.checkPeers`, with the same evidence as duplicity for the second case). A peer's word only ever refuses; a contact that lies can make a device refuse, never accept. A peer answers from what it has itself checked of the publisher (its floors), so one that has never accepted a list says nothing. The limit remains for a device with no peer that holds more, and an operator keeps it closed by destroying the keys of a witness retired from the publisher's identity.

## Consequences

- The publisher can be a single key held by one box, and later several keys, with the same checker and the same pin.
- `PinnedKeyID` and `PinnedKeyHex` are gone, replaced by the pin of decision 3; a build without a pin accepts no list. The signed-document reader in `measurementlist` (`Verify`, `SignedBytes`, the pinned key and its vectors) is deleted; the rules for a list's content stay in `measurementlist` (`FromContent`) and are tested through the credential's attribute block.
- An anchored list may say `list_version` 2 in its attribute block, and its entries then carry `environment`, `svn`, `smt` and `retired`, read by the same code as a signed list's.
- ADR-076 decision 7 stands and applies to whatever issues a list: the issuing tool refuses an entry marked as development.
- The floors (the highest list sequence and its hash, the newest place of the publisher's history this device has held, and the newest `published_at` accepted) never fall below the build's bundled snapshot.
- A peer watcher answers `POST /public/kel-tip` for the pinned publisher only, to a contact who signed the request, from the floors of this core.
- Tests: `identity-agent-core/measurementlist/anchored`. `verify_test.go` and `every_refusal_has_its_own_case_test.go` give a negative case to each refusal of the list, the anchor, the witnessing, the credential and the freshness guard, built so the bundle is right in every other respect. A few refusals are guarded twice (a repeated registry event, a withdrawal that does not follow its issuance) and fail on the other check as well when one is removed; a registry inception that is not the pinned one is refused earlier, as an event the history never sealed, so its own identifier check cannot be reached and is a second defence. `the_freshness_guard_test.go` forges a signed answer and has the witnesses name another event at the bundle's tip; `the_clock_floor_test.go` and `the_peer_watchers_test.go` hold decisions 4 and 9; `engine_test.go` is the engine's own output end to end.

## Superseded wording

"The list is Ed25519-signed by a publisher key pinned in the build" is false from this decision on. True instead: the list is issued under a pinned publisher identity and anchored in its witnessed key history. The old wording is allowed in ADR-076's own history.
