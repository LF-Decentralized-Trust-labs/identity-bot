# ADR-045 — Every asset gets an identity and a grant, and every grant comes from one schema template

**Status:** Accepted
**Date:** 2026-10-20
**Relates to:** ADR-032 (An identity can name who owns it, from its first event), ADR-042 (How an agent is reached, and who may manage it), ADR-044 (An authorized controller does the app's work)

## Context

An identity owns things that act for it: AI agents, websites, devices, services. Each is an
**asset**, and each gets a delegated identifier anchored in the owner's key log. That
answers *whose it is*.

It does not answer *what it may do*. For AI agents that was answered by a capability
grant, an ACDC the owner issued to the agent. Three things made that grant prove less
than it appeared to:

- **Its schema identifier was a placeholder string**, not the digest of a schema. A
  credential names its schema by digest so a verifier can fetch the document and
  confirm what the credential claims. A placeholder confirms nothing.
- **Verification could not pass on the engine that ships.** It required check results
  by names only an earlier engine reported, so every agent holding a grant was denied.
- **The owner's own events were unsigned.** Approving an agent, opening a registry and
  issuing a grant each append an interaction to the owner's key log. They were stored
  without a signature, so the log the agent published could not be verified by anybody
  else, and neither could anything anchored in it.

Every other kind of asset will need the same thing. Without a common shape, each kind
would grow its own grant format and its own verification path.

## Decision

**Every asset has two things, kept separate.**

- **Its identity:** a delegated identifier anchored in the owner's key log. Being
  delegated never implies permission.
- **Its grant:** a credential the owner issues to that identifier, from the owner's
  registry. Revoking it is an event in the registry's log that anyone can check.

Authority lives only in the grant. It can be narrowed, widened, lapsed or withdrawn
without touching the identity.

**Every grant schema is built from one template.** A schema is the whole ACDC (version,
identifier, issuer, registry, schema, attributes). The attribute block may appear
compacted to its own identifier, and nothing undeclared is accepted. Every grant's
attribute block carries the same shared attributes, in the same order:

| Attribute | Meaning |
|---|---|
| `d` | the attribute block's identifier |
| `i` | the asset's identifier: the holder |
| `dt` | when the grant was issued |
| `asset_type` | the kind of asset, fixed per schema, so the kind is readable from the credential |
| `name` | the asset's name when the grant was issued |
| `valid_until` | when the grant lapses; absent, it holds until revoked |

Each kind adds only its own attributes. The identifier of each schema is the Blake3-256
digest computed by the KERI library, never written by hand. A change to a schema is a
new schema with a new identifier.

**The AI agent grant adds only what the gateway enforces:** `capabilities`, the full list
of what the agent may invoke, and `resource_constraints`, the argument values it may use
per capability. It deliberately carries nothing else:

- **No role, prompt or model.** They configure the agent and are not authority. Changing
  one must not require a new grant.
- **No permission to delegate onward.** An AI agent cannot create agents, so the field
  would assert nothing.
- **No messaging recipients or conversation limits yet.** They arrive with agent
  messaging, as a new version of the schema. A field nothing enforces reads as a
  guarantee the software does not give.

**Issuing and verifying follow from that:**

- Attributes are checked against the schema before issuing.
- A grant is issued only into a registry. A grant that cannot be withdrawn is not one
  this software issues.
- Re-issuing a grant revokes the one it replaces. Otherwise a wider grant would stay
  valid beside a narrower one.
- Verification requires:
  - the credential's integrity
  - the accepted schema
  - the holder
  - the issuer's stored, signed key log
  - the issuance event in that log
  - no revocation
  - an unlapsed `valid_until`
- **An identity that holds its own key signs every event it writes into its own log.**
  An organisation holds its own key (ADR-032), so its approvals, registry and grants
  verify from the published log alone. An asset whose key this agent derived publishes
  its log with its own signature.
- Grant schemas are served at `/public/schemas/{said}`, exactly as their identifiers
  were computed over.

## Consequences

- A verifier holding only what was published can check an asset's whole chain: the
  owner's log, the asset's delegation, the grant, its schema and its revocation status.
- A new kind of asset needs only its own attributes. It gets the shared attributes,
  issuance rules and verification path unchanged.
- Grants issued under the placeholder identifier are not accepted, and the agents
  holding them must be issued a new grant.
- The other built-in schemas still carry placeholder identifiers. They are converted
  the same way when each is next worked on.
- Where an identity's key lives on another device, the events this agent writes for it
  are still stored unsigned until that device signs them. That is the same open gap as
  rotations and interactions sent from a client.
