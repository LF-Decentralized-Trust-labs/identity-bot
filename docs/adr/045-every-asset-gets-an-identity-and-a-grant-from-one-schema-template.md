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

### Who authorised it (amended 2026-10-22)

Version 1.1.0 of the template lets a credential name the credentials it rests on, in an
edges block, and carry the `request` that authorised it exactly as it was signed: whether a
machine or the identity's own key signed it, the signer, the exact string, the signature,
and `asked`: what the body asked for, and nothing else of it (the name, capabilities,
resource constraints and a nonce, if given). The body itself is not in the credential,
which anybody can fetch: a body can carry a system prompt, a model's address or the name of
a stored key. It is kept with the Identity Agent's record and goes in its export, and its
digest is in the signed string. `about` records what the request
named as the thing it acts on: the AI agent whose grant changes, or the machine being
approved as its body. The AI Agent Grant and AI Agent Body are issued at 1.1.0. A request a
machine made carries an edge `authorised_by` to that machine's Controller Grant (ADR-044).
One made on the device that holds the identity's key, without a signature, carries no
request: the issuer is the authority, and a verifier reports that rather than a check.

**The verifier's rule** (the open `authorisation.Check`, applied by the Identity Agent to
everything it issues and by anyone to an exported record):

1. The credential verifies against its own identifier, so nothing in it changed.
2. The string names the signer, and the signature over it verifies: for a machine, against
   the key its Controller Grant names; for the identity, against the key its own key log
   named.
3. For a machine: the edge names exactly the Controller Grant given, which is a Controller
   Grant, held by the signer, and issued by the credential's own issuer.
4. What was issued is what was asked: the same capabilities and limits, the same AI agent
   (by `about` or, when it is being created, by name), the same machine.
5. Given the body, its digest is the one the string carries, and `asked` is exactly what
   the body asked for. Without the body the check stops there and says so: it never reports
   a credential's link to its request as shown when it was not.
6. The request was made after the machine was granted, before its grant lapsed, and within
   five minutes of clock difference either side of the credential's issue. Given the
   issuer's key log and the credential's own log, the grant's revocation is ordered against
   the credential's issue by where each is anchored in that key log, not by the times they
   state; without them, by the time its transaction log states. `Check` does not validate
   the issuer's key log: a verifier must validate it, its signatures and its witnesses'
   receipts, before passing it, or the order it shows proves nothing.
7. One request authorises one credential. The Identity Agent refuses to issue a second on a
   request it has used; a verifier holding several credentials refuses any two carrying the
   same request (`authorisation.RequestDigest`).

The credential the Identity Agent issues for a new AI agent is issued to the identifier it
minted for it, so the identity's own anchored issuance is what ties the request to that one
AI agent; rule 7 keeps the request from being used for a second.

**What a verifier must add** to `authorisation.Check` when checking an exported record
rather than inside the Identity Agent: validate the issuer's key log and pass it, with the
credential's and the grant's own logs, so ordering is by anchoring; take each body from the
export and pass it, so rule 5 is shown; and apply rule 7 across everything it holds.

**A machine's own grant.** A Controller Grant issued on the owner's signed request carries
it like any other: the request must be `POST /api/controllers`, naming the machine the
credential is issued to, with the same key, label and grade. A machine or AI agent that
existed before grants is given one only this way, on the owner's request (ADR-044);
nothing issues one from what is on disk.

**Credentials issued while a grant is pending.** Where the identity's key is on another
device, a machine's grant is recorded with its credential pending there. A credential
issued on that machine's request meanwhile carries no edge, so it fails this check until it
is reissued once the grant's credential exists. That is reported, not hidden.

Credentials issued under 1.0.0 keep their identifiers and are still served. Those issued
before this Identity Agent issued its first 1.1.0 AI Agent Grant or Body are still honoured;
any issued after are not, since one could only have been issued to avoid naming anybody.

A third kind is built from the template: the **Controller Grant**, held by a machine
authorised to act for the identity (ADR-044).

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
