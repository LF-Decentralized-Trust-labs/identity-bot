# ADR-045 — Every asset gets an identity and a grant, and every grant comes from one schema template

**Status:** Accepted
**Date:** 2026-10-20
**Relates to:** ADR-032 (An identity can name who owns it, from its first event), ADR-042 (How an agent is reached, and who may manage it), ADR-044 (An authorized controller does the app's work)

## Context

An identity owns things that act for it: AI agents, websites, devices, services. Each is an
**asset**, and each gets a delegated identifier anchored in the owner's key log. That
answers *whose it is*.

It does not answer *what it may do*. For AI agents that was answered by a capability
grant: an ACDC the owner issued to the AI agent. Three things made that grant prove less
than it appeared to:

- **Its schema identifier was a placeholder string**, not the digest of a schema. A
  credential names its schema by digest so a verifier can fetch the document and confirm
  what the credential claims. A placeholder confirms nothing.
- **Verification could not pass on the engine that ships.** It required check results by
  names only an earlier engine reported, so every AI agent holding a grant was denied.
- **The owner's own events were unsigned.** Approving an AI agent, opening a registry and
  issuing a grant each append an interaction to the owner's key log. They were stored
  without a signature, so the published log could not be verified by anybody else, and
  neither could anything anchored in it.

Every other kind of asset will need the same thing. Without a common shape, each kind would
grow its own grant format and its own verification path.

## Decision

### Every asset has two things, kept separate

- **Its identity:** a delegated identifier anchored in the owner's key log. Being delegated
  never implies permission.
- **Its grant:** a credential the owner issues to that identifier, from the owner's registry.
  Revoking it is an event in the registry's log that anyone can check.

Authority lives only in the grant. It can be narrowed, widened, lapsed or withdrawn without
touching the identity.

### Every grant schema is built from one template

A schema describes the whole ACDC: version, identifier, issuer, registry, schema and
attributes. The attribute block may also appear compacted to its own identifier. Nothing
undeclared is accepted. Every grant's attribute block carries the same shared attributes,
in the same order:

| Attribute | Meaning |
|---|---|
| `d` | the attribute block's identifier |
| `u` | a salt, when the attributes are issued private; optional |
| `i` | the asset's identifier: the holder |
| `dt` | when the grant was issued |
| `asset_type` | the kind of asset, fixed per schema, so the kind is readable from the credential |
| `name` | the asset's name when the grant was issued |
| `valid_until` | when the grant lapses (date and time); absent, it holds until revoked |

The credential itself may also carry a top-level `u`. A salt matters because a grant's
attributes come from a small, guessable set: one fixed asset type and a few capability ids.
A compacted block without a salt could be recovered from its digest by trying them.

Each kind adds only its own attributes. The identifier of each schema is the Blake3-256
digest computed by the KERI library, never written by hand. Only the document's top-level
identifier is computed this way. The attribute block carries no identifier of its own,
because the library does not compute nested ones and a hand-written one would be a
placeholder again.

A change to a schema is a new schema with a new identifier. A schema that is replaced stays
served, so grants issued under it can still be checked.

### The AI agent grant adds only what the gateway enforces

- **`capabilities`:** the full list of what the AI agent may invoke.
- **`resource_constraints`:** per capability, per argument, the values it may use. Each
  constraint must name a capability the grant gives, and must list at least one value. An
  empty list reads as "nothing allowed", but the gateway treats it as "no limit".

It deliberately carries nothing else:

- **No role, prompt or model.** They configure the AI agent and are not authority. Changing
  one must not require a new grant.
- **No permission to delegate onward.** This software gives an AI agent no way to create AI
  agents of its own, so the field would assert nothing.
- **No messaging recipients or conversation limits yet.** They arrive with AI agent
  messaging, as a new version of the schema. A field nothing enforces reads as a guarantee
  the software does not give.

**Known limit.** Capability ids name definitions in the issuing Identity Agent's capability
registry. The grant does not pin which version of each definition it meant. So a definition
changed after issue changes what the grant allows, and a third party cannot read a
capability's meaning from the grant alone.

### Issuing

- Attributes are checked against the schema before issuing.
- A grant is issued only into a registry. A grant that cannot be withdrawn is not one this
  software issues.
- **A grant is re-issued before anything else changes.** If it cannot be issued, the AI
  agent's record and token keep what they had. The grant it replaces is revoked. If that
  revocation cannot be written to the registry, the old grant is still marked unusable
  locally.
- Constraints and lapse are kept on the asset and carried into every re-issued grant
  unless they are explicitly replaced. A grant re-issued without them would be a wider
  grant.
- Changes to one AI agent's grant happen one at a time.

### Verifying

A grant counts only if all of these hold:

- the credential is intact
- its schema is accepted
- its holder is the AI agent
- **its issuer is the AI agent's delegator.** Anybody can issue a credential naming an AI
  agent's identifier.
- the issuer's stored, signed key log verifies, **up to and including the event that issued
  it**, and that event's seal names this grant's issuance. Events written later say nothing
  about whether it was issued.
- it is not revoked
- its `valid_until` has not passed. Lapse is a rule of this schema; a generic ACDC verifier
  does not apply it.

The token's own scopes cap the result: if the two ever disagree, the narrower stands. Where
grants can be issued, an AI agent with no usable grant has no authority. Its stored ceiling
is used only by a build with no KERI engine.

### Signing

- **An identity that holds its own key signs every event it writes into its own log.** An
  organisation holds its own key (ADR-032), so its approvals, registry and grants verify
  from the published log alone.
- A signature the caller made over the event's bytes is kept as given.
- An asset whose key this Identity Agent derived publishes its log with its own signature.
  Before signing or publishing, the log found under the asset's name must belong to the
  asset. The KERI engine refuses to hold a second identity under a name that already holds
  one.
- Grant schemas are served at `/public/schemas/{said}`, exactly as their identifiers were
  computed over. Only schemas whose document digests to their identifier are served.

## Consequences

- A verifier holding only what was published can check an asset's whole chain: the owner's
  log, the asset's delegation, the grant, its schema and its revocation status.
- A new kind of asset needs only its own attributes. It gets the shared attributes, issuance
  rules and verification path unchanged.
- Grants issued under the placeholder identifier are not accepted. An identity whose log
  was written before its events were signed cannot have grants verified past those events,
  and must be founded again. The Identity Agent says so once at startup, naming the
  unsigned events.
- The other built-in schemas still carry placeholder identifiers, and are converted the
  same way when each is next worked on.
- Where an identity's key lives on another device, the events this Identity Agent writes for
  it are stored unsigned until that device signs them. Grants anchored after them cannot be
  verified by anybody else.
- Other credential schemas name their lapse `expiry_date` or `authorized_until`, as a date.
  Asset grants use `valid_until`, as a date and time, because a grant may lapse within a day.
