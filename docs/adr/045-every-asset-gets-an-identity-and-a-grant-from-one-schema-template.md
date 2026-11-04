# ADR-045 — Every asset gets an identity and a grant, and every grant comes from one schema template

**Status:** Accepted
**Date:** 2026-10-20
**Amended:** 2026-11-02 — An app is a kind of asset, with a grant and a body of its own (see §Amendment 1)
**Amended:** 2026-11-04 — A machine key's short code is 80 bits, not about 41 (see §Amendment 2)
**Amended:** 2026-11-04 — An AI agent's body may sign the request for an AI agent it creates; version 1.2.0 of the AI Agent Grant (see §Amendment 3)
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
- **No permission to delegate onward.** An AI agent may create AI agents only through
  `agent.create`, whose limits are `resource_constraints` on that capability, so no field
  of its own says whether it may (see Amendment 3).
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

*Amended 2026-11-04 (Amendment 3): a request may also be signed by an AI agent's body, for
an AI agent it creates, and the AI Agent Grant is issued at 1.2.0 to admit it. Rules 1 to 7
below hold for it as stated, with the signer and the grant they rest on changed as
Amendment 3 says.*

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
credential is issued to, with the same key, label and grade, the signer it named, if it
named one, and the same end. A machine or AI agent that existed before grants is given one
only this way, on the owner's request (ADR-044); nothing issues one from what is on disk.

**What the device holding the key checks before it signs**
(`authorisation.WhatSigningGrants`, run by that device's own core at `POST /api/signing-
requests/check`, and called from the apps through `agent_client`'s
`CheckingWhatYouAreAskedToSign`): the credential verifies against its own identifier; the
issuance event is of that credential, in its registry; the interaction is a well-formed
event of the credential's issuer whose one seal anchors exactly that issuance; and the
interaction extends the identity's key log as the device holds it. What is shown is read
from the credential: its kind, whom it grants, the machine's key and its fingerprint
(`authorisation.KeyFingerprint`, the code the owner compares, see Amendment 2), grade, signer, end,
capabilities and limits, never text the asking Identity Agent wrote. A registry's
inception is checked the same way (`WhatSigningRegisters`).

**Checked before it is written.** The Identity Agent builds each credential, checks it
against its request, and only then appends the interaction that anchors it, so a
credential that would fail is never in the key log, issued and then withdrawn. Once
appended it is checked again with the order of events read from the key log.

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

## Amendment 1 (2026-11-02): an app is an asset, with a grant and a body

*Amended 2026-11-02. Nothing above is changed.*

Each app that runs beside an Identity Agent (the task console first) runs on its own
small machine. Like an AI agent, an app is something the identity owns and lets act for it,
so it is an asset under this ADR: it has a delegated identifier, and a grant that is its only
authority. Two more kinds are built from the template, each with only the newer version
(1.1.0, with an edge to the grant of whoever authorised it):

- **App Grant** (`asset_type` `app`), what the app may ask of the Identity Agent. It adds
  `capabilities`, the ceiling, and `resource_constraints`, exactly as the AI Agent Grant does
  and checked the same way (ADR-050). It has **no role, prompt, model, messaging recipients
  or conversation limits**: an app has no brain, no model and no conversation inbox, so there
  is nothing of those to grant, and a grant that carried them would be refused as declaring
  an attribute the schema does not have.
- **App Body** (`asset_type` `app`), that one machine key is the body of one app. Its
  attributes are those of the AI Agent Body, the same grades and the same revocation. Only the
  asset type, the title and the description differ, so that an app's body is never mistaken for
  an AI agent's, and the reverse.

A machine becomes an app's body by the contract it already uses to become an AI agent's body:
the enrolment string, the sealed request, the signed requests (ADR-046) and the approval of
its signed request by a controller or the owner (ADR-059). Nothing in that contract names a
kind of asset, only the asset's identifier, so it is unchanged; an approving request for an
app's body is checked as it is for an AI agent's. The approval is
`POST /api/mcp/agents/{id}/bodies/{machine}/approve`, mounted by the AI agents add-on
(`identity-agent-addons/aiagents`), and the body credential names that machine in `about`.
Apps share this path under its AI-agent name for now: `{id}` is the asset's identifier, and
the path says nothing of the asset's kind. A machine a provider made is approved for an app on the
provider's signed vouch exactly as for an AI agent (ADR-059).

The published schemas are `app-grant-1.1.0.schema.json` and `app-body-1.1.0.schema.json` in
`identity-agent-core/contracts/asset-grants/`, byte for byte, and the body vectors include an
enrolment for an app.

**What this does not settle.** How an app's key is held (in a virtual chip or otherwise), its
encrypted stores, a relay and sign-in are later steps and are not in this contract. The
conversation verifier still accepts only an AI agent's body and grant: an app is not a party to
a conversation.

**Closed (2026-11-02).** The core provisions an app as it does an AI agent:
`asset.Handler.ProvisionAppAsset(displayName string, capabilities []string, validUntil *time.Time,
constraints map[string]interface{}) (*Asset, error)` mints an asset of type `app` with its own
delegated identifier, and the Identity Agent issues its App Grant from the owner's registry with
`issueCapabilityGrant`, recorded as an AI Agent Grant is (and, where the key is on another device,
left for that device to sign). An app and an AI agent cannot share a name, since the engine keys
identities by it. Three seams are closed with it:

- `checkAskedFor` (`identity-agent-core/authorisation/request.go`) checks an App Grant against the
  request that asked for it, exactly as it does an AI Agent Grant (name, capabilities and limits), at the route that creates an app,
  `POST /api/hosted-apps` (mounted by the apphosting add-on), and only there: no route changes an app's capabilities yet,
  and when one is added it is bound in `checkAskedFor` with it. A request to grant an AI agent is
  not accepted as an app's, nor the reverse. The request does not name the app it creates, so
  nothing ties the grant to an asset beyond its name.
- `grantShown` (`identity-agent-core/authorisation/what_is_signed_is_what_is_shown.go`) shows an
  App Grant, as kind `app`, with its name, capabilities, limits and end, so a device holding the
  owner's key can be asked to sign one.
- Looking up the grants an asset holds (`GrantsHeldBy`, `FindCapabilityGrant`) covers an app's
  App Grant, so whatever revokes or removes an app can find and withdraw it. That is a different
  list from the grants a gateway admits, below.
- The edge lookup in `identity-agent-core/server/whoever_authorised_it_is_named.go` accepts the
  App Grant and App Body when it finds when this Identity Agent first issued a credential that names
  who authorised it.

These seams are still open, and each is refused rather than half-working:

- An App Grant signed on another device is kept by this Identity Agent only once an add-on
  registers the app grant kind; until then it is not taken up. No add-on registers it yet.
- Re-issuing an app's grant while the owner's key is on another device withdraws the old App
  Grant before the new one is signed, which leaves the app with none until it is; no route
  re-issues an app's grant yet, and the one that does must keep the old grant until the new one
  is taken up.
- No route issues an App Grant or an App Body yet. `ProvisionAppAsset` and the issuance exist; no
  route in the Identity Agent calls them; the apphosting add-on's `POST /api/hosted-apps` is the
  route that will, and no route yet changes an app's capabilities.
- The Identity Agent's own list of grant schemas it honours as capability grants
  (`CapabilityGrantSchemaSAIDs`, read by add-ons) is unchanged, so no gateway admits an app on its App
  Grant yet. Admitting an app's grant at the gateway belongs to step 3 (apps reached through the
  relay and making calls), and is decided there.

The check of a body's approval is tied to the asset the path names: the caller gives the check
a lookup from the path's `{id}` to that asset's pairwise AID and kind, and the body credential
must be held by that AID and be the AI Agent Body for an AI agent or the App Body for an app.
No lookup, or an asset it does not know, refuses.
The lookup is given the path's `{id}` and the body credential's holder. An Identity Agent that
keeps its assets answers by `{id}`. An offline verifier has only credentials, and a grant names
its asset in `about` only when the request that asked for it named one, so it answers by the
grant the holder holds: that grant gives the kind, and its `about`, where it has one, must be
the `{id}`. The check also requires the path to be the one the route mounts,
`/api/mcp/agents/{id}/bodies/{machine}/approve`.

## Amendment 2 (2026-11-04): a machine key's short code is 80 bits

`authorisation.KeyFingerprint` is the short code a person compares to confirm a machine's key.
It was eight characters of the key's Blake3 text form (QB64), in two groups, upper-cased. The
first character after the type code takes only 16 values and upper-casing merges letters, so
the code carried about 41 bits. Someone who knew a person's code could make a different key
with the same code on a GPU in hours, and the person would confirm the wrong key.

It is now the first 80 bits of the raw Blake3-256 digest (not its QB64 text), written as 16
Crockford base32 characters in four groups of four, `XXXX-XXXX-XXXX-XXXX`. Crockford has no
I, L, O or U and is case-insensitive, so nothing is lost by upper-casing or by reading a
code aloud. The domain string was `key-fingerprint/v1` and the version change means an old code
never equals a new one. A key of the machine that was compared under the old form must be
compared again.

Exactly, so that another implementation reproduces it byte for byte:

1. Take the public key as its QB64 text, with leading and trailing white space (space, tab,
   CR, LF, and the other Unicode white space Go's `strings.TrimSpace` removes) trimmed. An
   empty key has no code.
2. Hash the UTF-8 bytes of `key-fingerprint/v2` + one LF (0x0A) + that text with plain,
   unkeyed BLAKE3, 256-bit output.
3. Take the first 10 bytes of the digest (80 bits). Read them most significant bit first, in
   sixteen 5-bit groups, with no padding.
4. Write each group as a character of `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (value 0 is `0`,
   value 31 is `Z`), and put a `-` after the 4th, 8th and 12th.

Vector: the key `DAtHgj5xCV3Vm-eKwnHFdu84n4e2RWGrB8-aTrzQLSBB` has the code
`M8PN-ME83-7RPK-D6FF`.

The code is derived from the key each time it is shown, with one exception: an approval
queued before this change keeps the old eight-character code in its stored one-line summary,
while its details show the new one. They differ visibly, which is safe: compare the new one.

Pinned in `identity-agent-core/authorisation/a_key_code_is_too_long_to_forge_test.go`: two
keys with their codes, and every one-bit change of a key giving a different code. There was no
published vector file for this code, so none is regenerated.

## Amendment 3 (2026-11-04): an AI agent names its creator

An AI agent whose grant holds `agent.create` may ask the Identity Agent to create another AI
agent, and to set its repositories, over its body's own signed channel
(`POST /api/agent-host/agents` and `PUT /api/agent-host/agents/{id}/github`). The grant
issued for the AI agent it created must say who authorised it, as every grant does, and here
the authority is the creating AI agent, not the owner and not a machine.

**A third kind of signer.** A credential's `request` has a `kind`: `controller` (a machine,
signed over `IA-CONTROLLER-REQ`), `owner` (the identity's own key) and now `ai_agent_body`.
The signer of an `ai_agent_body` request is the machine, the body, that holds an AI Agent
Body credential for the creator. The string it signs is the body request of ADR-046,
`IA-BODY-REQ-V3`: the Identity Agent it was for, the body, the method and target, the time,
a nonce, the digest of the request's body, then the work item, reason and session. A body's
request is accepted only at the body's own routes (`/api/agent-host/...`), and an owner's or
machine's request only at theirs: one kind of request cannot stand for the other's.

**The creator chain.** The new grant's `authorised_by` edge names the creator's AI Agent
Grant. The creator's AI Agent Body credential is given beside it. `authorisation.Check`
verifies:

1. the creator's grant verifies against its own identifier, is the one the edge names, was
   issued by the same Identity Agent as the new grant, holds `agent.create`, and is not the
   new AI agent's own;
2. the creator's body credential verifies, was issued by that Identity Agent, is for the
   same creator, and names the key that signed the request;
3. the signature over the exact string, by that key, verifies, and the string names this
   Identity Agent as the one it was for;
4. both credentials were in force when the request was made (after they were granted, before
   they lapsed) and neither was revoked before the new grant was issued, ordered as in rule 6
   above;
5. the new AI agent is no more powerful than its creator. It holds only capabilities the
   creator's grant holds, and for every argument the creator's grant limits to some values,
   the new grant limits it to some of those; a limit the creator has and the new grant leaves
   off is wider, and refused. A list of values that is empty is refused in either grant, as
   the schema refuses it. Where the creator's grant has a `valid_until`, the new grant has one
   too, and it is no later: an AI agent cannot outlive its creator. An AI agent cannot create
   a more powerful one.

**What is not verified.** The core does not enforce any count or resource limit on how many
AI agents a creator may create, or how much they may use, even where the creator's grant
states one in `resource_constraints` on `agent.create`. That is enforced by the party that
issues the creator's grant, at the time it asks
for the new grant, and a verifier reading the credentials afterwards cannot tell whether it
did. Only the comparison in point 5 is made here.

**Version.** The AI Agent Grant is issued at 1.2.0, which admits the `ai_agent_body` request
kind. Versions 1.0.0 and 1.1.0 remain honoured as they were: a 1.1.0 grant is checked
against what was asked for, counts toward when this Identity Agent began issuing grants that
name who authorised them, and is kept under the version it was issued in. Software that does
not know 1.2.0 sees a schema it does not recognise and refuses the credential; it never
reads one as a version it does know.

Worked examples, accepted and refused, each refusal breaking one rule:
`identity-agent-core/authorisation/ai-agent-body-request-vectors.json`, checked independently
by `identity-agent-core/contracts/check_ai_agent_body_request_vectors.py`.
