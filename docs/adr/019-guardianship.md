# ADR-019: Guardianship

**Status:** Accepted · amended 2026-11-14 (the amendment below replaces how a guardian holds authority)
**Date:** 2026-03-22 · amended 2026-11-14
**Deciders:** Rob Andersen

---

# Amendment — 2026-11-14: guardianship is a multi-signature on the dependent's own identifier

> **This amendment replaces the delegation in the rest of this document.** Where
> the text below says guardianship is a delegation between two Guardianship
> P-AIDs, the amendment governs. The passages it replaces carry a note pointing
> here; everything not named in "What changes" is unchanged and still Accepted.

## Why the delegation is replaced

The decision below used delegation (`dip`/`drt`) between two purpose-bound
identifiers so that no Root AID was published. That removed the Root AID from
the picture but left the rest of the problem in place:

- **A delegated inception names its delegator in an event anyone can read.** The
  guardian's Guardianship P-AID is written into every event of the dependent's
  key history. A verifier who sees any credential of the dependent can walk to
  the guardian's identifier and see that this person is the dependent's guardian.
- **The dependent is not sovereign.** A delegated identifier can be rotated only
  with its delegator's approval, and emancipation had to end the identifier and
  found a new one, which strands every credential issued to the old one.
- **It needed a second identifier per relationship** (two Guardianship P-AIDs, a
  new subclass of pairwise identifier, a hard dependency on the relay's pairwise
  work) to get a result a multi-signature gives directly.

## The decision

**Every human dependent has an identifier of their own, founded by an ordinary
standalone inception (`icp`), and guardianship is a multi-signature over that
identifier.** A guardian's signing key joins the dependent's key set as an
additional signer; the signing threshold and the set of keys together are the
authority relationship. Nothing is delegated.

1. **The dependent's identifier is never delegated.** A newborn's is founded by
   the guardian on the dependent's own isolated Identity Agent instance; an
   adult who comes under guardianship keeps the identifier they already have.
   Neither is replaced.
2. **A guardian joins by rotation.** A newborn's identifier names the
   guardian's key in its inception, in both the current key set and the next-key
   commitment. For an identifier that already exists, KERI requires the keys a
   rotation makes current to be the ones the event before it committed to in its
   next-key digest, so a new guardian's key takes two rotations: the first
   commits a next key set that includes it, and the second makes that set
   current at the threshold the template names.
3. **Only keys appear, never the guardian's identifier.** The dependent's key
   history shows that its key set changed on a date. It does not name the
   guardian's identifier, so no verifier can walk from the dependent to the
   guardian. The guardian's key placed there is made for this relationship, not
   the key of the guardian's own identifier, because the same public key in two
   key histories would link them.
4. **Co-guardians and courts are further signers.** A second parent, an
   attorney, a court's signing key and a reserved emergency signer are each
   another key in the set, with a threshold that fits (two of three leaves no
   tie; two of two needs a tie-break rule agreed when the guardianship is made).
5. **Changing guardian is the same pair of rotations.** The first commits a
   next key set with the incoming guardian's key in place of the outgoing one;
   the second makes it current. The outgoing guardian's key signs until then, so
   there is no moment the dependent is uncontrolled.
6. **Emancipation is a rotation, not a new identifier.** A rotation reduces the
   key set to keys the dependent alone holds (committed in the next-key digest
   beforehand, as in item 2). The identifier, its key history,
   its credentials and its contacts are unchanged. If a guardian is needed again,
   a rotation brings one back.
7. **The key history is the proof.** The guardian's authority is that their key
   signed the rotations that made the multi-signature; no third party is
   needed for it to exist. What the key history does not say is who the guardian
   is in the world: where that must be shown to a school, hospital or court, an
   optional Guardian credential names them and refers to the dependent's identifier.
8. **What a guardian may do is enforced by threshold, not by the protocol.**
   The categories (identity, financial, medical, legal, communication) and levels
   (full, co-sign, view, blocked) are a policy the dependent's Identity Agent
   enforces by asking for more or fewer of the key set's signers before it acts
   on each kind of request. KERI itself signs every event at the one threshold
   the key set states; the key history knows nothing of categories.
9. **Delegation is still right for what is not a person.** An asset acting for
   its owner, such as an AI agent or a bot, is delegated (ADR-045); only human
   guardianship leaves delegation.

This is standard KERI: multi-signature inception and rotation with next-key
digests, no new event type. The KERI engine (ADR-037) therefore needs
multi-signature inception and rotation, which it does not perform yet; it does
not need delegated inception or rotation for guardianship.

## What changes in this document

| Passage | Now |
|---|---|
| Context, "Privacy constraint" | Replaced: no delegation, so no delegator is exposed |
| Guiding principle 2 | Replaced by item 1-3 above |
| "Guardianship = KERI Delegation Between Guardianship P-AIDs" | Replaced by the decision above; the guardian's actions become: rotations to add or change a guardian (items 2, 5), change the threshold by rotation, and end guardianship by an emancipating rotation (item 6) |
| "Emancipation = Authority Transfer" | Replaced by item 6; there is no new inception and no topology change |
| Data model | `guardian_guardianship_raid`, `dependent_guardianship_raid` and `co_guardian_raids_json` become `dependent_aid` (the dependent's own identifier), `multisig_participants_json` (the public keys in the set, each with its role) and `multisig_threshold` (kept); no identifier of any guardian is stored |
| Consequence 8 (relay is a prerequisite) | Withdrawn: guardianship no longer uses pairwise identifiers |
| Consequence 9 (delegated inception in the driver) | Replaced: the KERI engine (ADR-037) must perform multi-signature inception and rotation |
| Consequence 10 (store migration) | The legacy delegation fields are replaced by the three above; guardianship has not shipped, so it is still a hard migration |

Unchanged: one identifier per Identity Agent instance, hosting of the
dependent's instance, the four templates (their emancipation triggers become
rotations), contact labels, navigation, the API surface and phasing.

---

## Context

The Identity Agent manages an individual's user-controlled digital identity. However, many people cannot — or should not — manage their own identity independently:

- **Minor children** have no legal capacity to manage identity; a parent or legal guardian acts on their behalf.
- **Elderly family members** may become incapacitated and need a family member or attorney to manage their identity.
- **People with disabilities** may require ongoing guardianship for identity decisions.
- **Temporary situations** (medical events, travel, short-term care) may require time-limited delegation.
- **End of life** requires a way to transition identity management to an estate executor or designated family members.

KERI already provides the cryptographic primitives needed for all of these scenarios — delegated AIDs, multi-sig, and pre-rotation commitments. This ADR establishes how these primitives are exposed to users through the Guardianship feature, including the device/hosting architecture for dependent identities.

> *Replaced by the 2026-11-14 amendment above.*

**Privacy constraint.** Vanilla root-to-root KERI delegation would expose both parties' Root AIDs (R-AIDs) to any verifier who sees the dependent's credentials, because the dependent's DIP event contains a `delegator` reference that anyone with the child KEL can walk. That violates the Root AID shielding rule established by the Identity Agent's **Agent URL Relay** architecture, which defines Pairwise AIDs as the mechanism for keeping the Root AID private. To satisfy both guardianship's need for KEL-anchored authority and the shielding rule, this ADR specifies that **guardianship delegation is between two purpose-bound Guardianship P-AIDs — never between Root AIDs.** KERI does not distinguish "root" from "non-root" delegators, so this uses the existing `dip`/`drt` primitives unchanged; only the AIDs selected to participate change.

→ *Related: ADR-006 (Topology), ADR-014 (Key Custody), ADR-018 (Desktop Navigation); Agent URL Relay architecture (defines Pairwise AIDs and the Guardianship P-AID subclass)*

---

## Decision

### Guiding Principles

> *Principle 2 is replaced by the 2026-11-14 amendment above.*

1. **One AID per Identity Agent instance, always.** A dependent's AID is never co-located on the guardian's device within the same Identity Agent instance. Every identity gets its own isolated instance with its own data directory and key storage.

2. **KERI delegation between Guardianship P-AIDs is the foundation.** Every guardianship relationship maps to a KERI delegation between two purpose-bound **Guardianship P-AIDs** — a subclass of Pairwise AID defined by the Identity Agent's Agent URL Relay architecture. The guardian creates a Guardianship P-AID for this specific relationship and acts as the delegator; the dependent's isolated Identity Agent instance holds a Guardianship P-AID created via delegated inception (DIP) against the guardian's Guardianship P-AID and acts as the delegatee. Neither party's Root AID participates in the delegation chain. This reuses the existing Topology #2 (Remote Controller WITHOUT Root Keys) pattern from ADR-006 — the dependent's instance holds no Root AID, only its Guardianship P-AID.

3. **Jurisdiction-aware but not jurisdiction-dependent.** Guardianship records capture jurisdiction at creation time and adapt form fields accordingly, but jurisdiction does not restrict core guardianship operations. Users can change jurisdiction (when they move, etc.) and users without a fixed address set jurisdiction to "Unknown" or "Cross-border" with the most permissive parameter set.

4. **Plain language over technical vocabulary.** The four sections use consumer terms: **My Dependents**, **My Guardians**, **My Will**, **Estate Planning**. Templates use consumer terms: "Minor Child", "Elderly Family Member", "Person with a Disability", "Temporary Guardianship". Contact labels are directional plain English: "You are guardian of [Name]".

5. **Black Box Infrastructure Stewardship for dependent provisioning.** Dependent identities without a physical device are provisioned via Black Box Infrastructure Stewardship providers (see the compliance Doctrine 1) — the provider operates TEE-sealed enclaves and provably cannot access key material or user data. A given build may pre-configure a default provider. The term "cloud hosting" is not used — see the compliance model.

6. **Phased delivery.** Phase 0: P-AID primitives. Phase 1: My Dependents (reworked creation flow). Phase 2: My Guardians. Phase 3: My Will. Phase 4: Estate Planning. Phase 5+: Family section, custom types, court integration.

---

### Guardianship = KERI Delegation Between Guardianship P-AIDs

> **Replaced by the 2026-11-14 amendment above** — guardianship is a multi-signature on the dependent's own identifier, not a delegation.


Each guardianship relationship maps to a KERI delegation between two Guardianship P-AIDs:

| Role | KERI Concept | AID Used | Identity Agent Topology |
|---|---|---|---|
| Guardian | Delegator | **Guardianship P-AID** — a purpose-bound Pairwise AID the guardian creates specifically for this relationship. NOT the guardian's Root AID. Not reused across guardianships. | Topology #1 (Standalone) or existing topology |
| Dependent | Delegatee | **Guardianship P-AID** — created via delegated inception (DIP) with `delegator = guardian's Guardianship P-AID`. Held inside the dependent's isolated Identity Agent instance. | Topology #2 (Remote Controller WITHOUT Root Keys) |
| Co-guardian | Multi-sig participant on the delegation | A separate Guardianship P-AID held by the co-guardian, participating in a multi-sig delegation seal | Multi-sig threshold on the dependent's Guardianship P-AID |

**Root AIDs never appear in the delegation chain.** The guardian's Root AID is not a delegator; the dependent's instance has no Root AID at all while under guardianship. Because the delegation lives entirely at the P-AID layer, third-party verifiers who see the dependent's credentials cannot walk the KEL back to either party's Root AID — the Root AID shielding property is preserved.

**keripy semantics are unchanged.** KERI does not distinguish "root" from "non-root" delegators. The existing `dip` / `drt` event types and keripy's delegation helpers work without modification; only the AIDs selected to participate change.

The guardian can:
- **Rotate** the dependent's Guardianship P-AID keys by issuing a delegated rotation (DRT) — required when a dependent's device is lost or compromised
- **Revoke** the delegation by rotating the guardian's Guardianship P-AID in a way that abandons the delegation seal (permanent KEL record)
- **Emancipate** — perform a final DRT transferring authority to keys held solely by the dependent, then the dependent's instance performs a new standalone inception to establish its own Root AID

### Dependent AID Hosting

The dependent's Identity Agent instance runs on a **separate, dedicated device** — either provisioned via a Black Box Infrastructure Stewardship provider or on a physical device. There are no plans to support running multiple AIDs within a single Identity Agent instance on the same device.

The Add Dependent flow branches early:
- **Connect existing Identity Agent** — the dependent already has a functioning Identity Agent; pair via QR/link
- **Create new Identity Agent** — install on a separate device, OR instant creation via a Black Box Infrastructure Stewardship provider (the build's default provider; see the compliance Doctrine 1)

**Why black box infrastructure is the recommended default for dependents without devices:**
- Instant provisioning — no hardware needed
- Natural multi-sig — multiple guardians connect as remote controllers to the same instance
- Clean emancipation path — final delegated rotation transfers authority to keys held solely by the dependent, then the dependent's instance performs a new standalone inception to establish its own Root AID; data stays in place
- TEE security — provider enclaves are cryptographically attested; operator cannot access key material or user data
- No storage burden on the guardian's device

**Black Box Infrastructure Stewardship providers** are configured in Settings > Service Providers. A given build may pre-configure a default provider. Any service that runs isolated Identity Agent instances in TEE-backed enclaves and exposes the standard Identity Agent API qualifies as a provider.

### Guardianship Templates

Four built-in templates pre-configure the KERI delegation parameters, default permissions, and lifecycle triggers:

| Template | Duration | Authority | Emancipation Trigger | Multi-sig Default |
|---|---|---|---|---|
| **Minor Child** | Until emancipation | Full control | Age 18 (configurable) | Optional (other parent) |
| **Elderly Family Member** | Indefinite | Co-sign or full | None (manual revocation) | Recommended (family + attorney) |
| **Person with Disability** | Indefinite | Co-sign or full | None | Recommended |
| **Temporary Guardianship** | Time-limited | Scoped | Expiration date | Optional |

Custom guardianship types are deferred to a later release.

### Emancipation = Authority Transfer

> **Replaced by the 2026-11-14 amendment above** — guardianship is a multi-signature on the dependent's own identifier, not a delegation.


When a dependent is emancipated (age trigger, manual action, or court order):

1. Guardian performs a final delegated rotation transferring signing authority to keys held solely by the dependent
2. Dependent's device performs a new inception to establish a standalone AID
3. The old delegated AID's KEL records the full chain of custody (provenance preserved)
4. Dependent transitions from Topology #2 → Topology #1 (Standalone)

### Contact Role Labels

Contacts involved in guardianship relationships display a directional role label:

| Viewer's Role | Label |
|---|---|
| I am their guardian | "You are guardian of [Name]" |
| They are my guardian | "[Name] is your guardian" |
| We are co-guardians | "Co-guardian with you for [Dependent Name]" |

### Navigation Placement

| Nav Location | Content |
|---|---|
| **Guardianship** (top-level nav) | My Dependents, My Guardians, My Will, Estate Planning |
| **My Data > Family** (future, when My Data is implemented) | Read-only family tree, succession status summary (documents owned by the data taxonomy) |

### Data Model

> **Replaced by the 2026-11-14 amendment above** — guardianship is a multi-signature on the dependent's own identifier, not a delegation.

**GuardianshipRecord** stored in SQLite (`guardianships` table):

| Field | Type | Description |
|---|---|---|
| `id` | TEXT PK | UUID |
| `type` | TEXT | minor_child, elderly, disability, temporary |
| `guardian_guardianship_raid` | TEXT | Guardian's Guardianship P-AID prefix (the delegator). Purpose-bound to this relationship only. Never the guardian's Root AID. |
| `dependent_guardianship_raid` | TEXT | Dependent's Guardianship P-AID prefix (the delegatee). Created via DIP event with `delegator = guardian_guardianship_raid`. Held inside the dependent's isolated instance. |
| `dependent_name` | TEXT | Display name |
| `status` | TEXT | active, expired, revoked, emancipated |
| `hosting_type` | TEXT | cloud, device |
| `hosting_url` | TEXT | Infrastructure provider URL (if cloud) |
| `created_at` | TEXT | ISO 8601 timestamp |
| `updated_at` | TEXT | ISO 8601 timestamp |
| `emancipation_json` | TEXT | JSON: {type, value} |
| `co_guardian_raids_json` | TEXT | JSON array of co-guardian Guardianship P-AID prefixes (never Root AIDs) |
| `multisig_threshold` | INTEGER | Multi-sig threshold (0 = no multi-sig) |
| `metadata_json` | TEXT | JSON: template-specific fields |

**No Root AID fields.** The record intentionally does not store either party's Root AID. The pre-existing `guardian_aid`, `dependent_aid`, and `delegated_aid_prefix` fields from the earlier draft of this ADR are replaced by the two `_guardianship_raid` fields above. A migration will be required when the existing code in `identity-agent-core/store/store.go` (which still uses the legacy field names) is updated to match this decision.

### API Surface

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/guardianship` | List all guardianship relationships |
| `POST` | `/api/guardianship` | Create guardianship (triggers KERI delegation) |
| `GET` | `/api/guardianship/{id}` | Get guardianship detail |
| `PUT` | `/api/guardianship/{id}` | Update guardianship |
| `DELETE` | `/api/guardianship/{id}` | Revoke guardianship |
| `POST` | `/api/guardianship/{id}/emancipate` | Trigger emancipation |

### Future Phases (Not This ADR)

- **Succession Planning** — pre-rotation commitment, multi-sig key holder designation, credential triage configuration
- **Estate Management** — succession activation, credential triage execution, estate AID management
- **Custom Guardianship Types** — user-defined templates with custom parameters

---

## Consequences

1. **New SQLite table** (`guardianships`) added to the identity store via migration. Schema uses `guardian_guardianship_raid` and `dependent_guardianship_raid` fields — no Root AID fields.
2. **Store interface extended** with guardianship CRUD methods.
3. **New REST API surface** under `/api/guardianship`.
4. **Desktop sidebar gains a "Guardianship" collapsible section** (ADR-018 canonical structure updated).
5. **Contact cards gain role labels** — directional guardianship badges alongside existing contact type badges.
6. **Identity Agent Infrastructure Service Provider** established as a new provider type in Settings > Service Providers (a default provider may be pre-configured; additional providers configurable).
7. **One AID per instance rule** is now explicit policy — no same-device multi-AID.
*(Replaced by the amendment — see "What changes".)* 8. **Agent URL Relay is a hard prerequisite.** Guardianship cannot ship until the Agent URL Relay architecture (Pairwise AIDs, Root AID isolation) is built — Guardianship P-AIDs are a subclass of Pairwise AIDs defined there.
*(Replaced by the amendment — see "What changes".)* 9. **Python KERI driver must gain delegated-inception support.** The current `drivers/keri-core/server.py` has `/inception` and `/rotation` endpoints that produce standard (non-delegated) events. A `delegator` parameter (or a dedicated `/delegation/inception` endpoint) must be added so the dependent's instance can produce a DIP event anchored to the guardian's Guardianship P-AID. Same for `/delegation/rotation` (DRT) to support guardian-authorized rotation, revocation, and emancipation. No protocol-level spike is required — KERI does not distinguish root from non-root delegators, so keripy's existing delegation primitives work unchanged.
*(Replaced by the amendment — see "What changes".)* 10. **Existing `GuardianshipRecord` in `identity-agent-core/store/store.go` needs a schema migration.** Current fields `GuardianAID`, `DependentAID`, `DelegatedAIDPrefix` are replaced by `GuardianGuardianshipRAID`, `DependentGuardianshipRAID`. Since guardianship has not yet shipped in production, this can be a hard migration (no dual-write / back-compat shim needed).

---

## References

- ADR-006: Standardized Topology — 3 States × 2 Device Types
- ADR-014: Key Custody, Backend Server Mode, Migration, and Data Partitioning
- ADR-018: Desktop Navigation Structure
- Plan doc: `2. Plans/guardianship.md`
- Tasks: `1. Strategy/tasks.md` → "Guardianship" section
