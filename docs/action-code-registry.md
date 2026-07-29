# The Identity Agent Action Code Registry

**Status:** Active · v1.0 · **Steward:** Grape ID (initial) · **License intent:** Open (this registry + the framework are open source; implementations may be open or proprietary)

*Formalizes the actions system decided in [ADR-017](adr/017-share-actions-system.md): this is the canonical, living registry of action codes + their schemas.*

> **Data vs. spec.** The **canonical registry is machine-readable data**:
> [`identity-agent-core/actions/registry.json`](../identity-agent-core/actions/registry.json),
> validated by
> [`registry.schema.json`](../identity-agent-core/actions/registry.schema.json).
> That JSON is the single source of truth — it seeds `identity.db` and is imported
> by any Identity Agent (see ADR-017). **This document is the *spec*** — it explains
> how the registry works, its governance, and how to propose codes; it does not hold
> the data. §10 below is a human-readable rendering of `registry.json`, which is
> authoritative if the two ever differ.

---

## 1. Why this exists

Identity Agents talk to each other by scanning a small pointer (a QR code or a
link) that resolves to a signed **Ask** — a request to *do something*: sign in,
add a contact, become an employee, present a credential, pay, co-sign a document.

For any two agents — built by anyone — to understand each other, they must agree
on **what each request means and what data it carries.** They do **not** need to
agree on *how* each agent fulfils it.

Every action has an **Identity Agent on each side** — and the registry is neutral
to *who* those parties are. A side may be a person or an organization, and the
pairing can be **individual↔individual** (paying a friend — no organization
involved anywhere), **individual↔org**, **org↔org**, or **one-to-many /
many-to-one**. This is an *agent-to-agent* language, not an "individual vs. org"
one; the registry fixes only what each action *means*, never who is allowed to be
on either end.

This is the same split that made the internet work:

| Layer | Internet | Identity Agent |
|---|---|---|
| **Canonical contract** | HTTP status codes, methods, MIME types (one registry, via IANA/IETF) | **Action codes + their schemas** (this registry) |
| **Free implementation** | every website handles `404` its own way | every agent fulfils an action its own way |

The **universality lives in the contract** (a number → its meaning + data shape).
The **diversity lives in the implementation.** They never conflict, because the
number→meaning binding is **canonical and collision‑free** — there is exactly one
registry, and you cannot privately redefine an assigned code.

> **This is the answer to "won't lots of implementations fragment the language?"**
> No. Anyone can build a different *implementation*; nobody can mint a conflicting
> *code*. New codes are proposed **to this one registry**, not invented in silos.

---

## 2. Terminology (and one disambiguation)

- **Ask** — a signed request an agent scans. Carries an **action code** (`t`).
- **Action code (`t`)** — an integer naming a *reusable interaction pattern*
  (e.g. `1 = login`). This document assigns and defines them.
- **Action schema** — the data an Ask of a given code carries + the outcome contract.
- **Identity Agent** — software that scans an Ask and acts on it under the Identity
  Agent Protocol (Grape ID or otherwise). Always "Identity Agent," never bare
  "Agent" — to avoid confusion with *AI* agents. Software that doesn't follow this
  protocol simply isn't an Identity Agent in this document.
- **Governance** — here means the **stewardship process for this registry**: how
  codes are proposed, reviewed, assigned, and versioned. It is a *standards*
  process (think IANA/IETF), **not** the Grape ID *Governance Gateway* product
  feature (an org's internal approval/consent surface). Different things; the name
  collision is noted so we keep them separate.

---

## 3. The Ask envelope (the protocol layer — open)

Every Ask is JSON with a common envelope. A conforming Identity Agent reads `t`, looks it
up in the registry, and dispatches:

```jsonc
{
  "v": "ASK1",            // envelope version
  "t": 1,                 // ACTION CODE — the registry key
  "signer_oobi": "...",   // how to resolve the minting party's key (KERI OOBI)
  "sig": "0B...",         // signature over the canonical Ask by the minter
  // ...action-specific fields defined by the code's schema...
}
```

The scan pipeline (open, in the framework) is two calls:

1. **decode** — fetch the Ask, verify `sig` against the signer's KEL, read `t`,
   and return a **Preview** (a human-facing "here's what's being asked").
2. **execute** — after the user approves, run the action.

A conforming Identity Agent implements a small handler per code:

```
Action() string                      // the code's canonical name
Preview(ctx) -> GenericPreview        // what the user is shown before deciding
Execute(ctx, decision) -> result      // what happens on approval
```

`GenericPreview` (the universal preview contract):

```jsonc
{
  "t": 1, "action": "login",
  "title": "Sign in",
  "subtitle": "Sign in to Acme Corp",
  "counterparty": "E...AID",
  "details": [ { "label": "Website", "value": "acme.com" } ],
  "warning": "optional caution string",
  "tier_options": ["general","trusted","professional"],  // optional escalation
  "default_tier": "general"
}
```

> Because the **envelope + pipeline + preview contract are open**, any agent can
> read *any* registered action and render a sane consent screen — even for a code
> whose rich implementation it doesn't have.

---

## 4. What an action code entry looks like (the registry schema)

Each registered code is one entry with these fields:

| Field | Meaning |
|---|---|
| `code` | the integer `t` (canonical, immutable once assigned) |
| `name` | short canonical name (`login`, `add_contact`, …) |
| `summary` | one line: the interaction pattern |
| `request_schema` | the action-specific fields the Ask carries (names, types, required) |
| `preview_contract` | what a compliant Preview must convey (title/subtitle/details) |
| `outcome` | what a compliant Execute achieves (the effect, not the code) |
| `tiers` | optional escalation levels the action supports (if any) |
| `who_mints` | which party creates this Ask (RP website, a peer, an org, …) |
| `status` | `active` · `reserved` · `deprecated` |
| `version` | schema revision (additive changes bump minor; see §7) |

An entry defines the **contract**, never the code that fulfils it. A reference
implementation MAY be linked, but is not required for a code to be canonical.

---

## 4a. Canonical schema *values* — closed enums vs. open fields

**The `t` code alone is not enough.** For agents to truly interoperate, the
*schema* a code carries must be canonical too — including, critically, the
**allowed values of interoperability-bearing fields.** This is the difference
between a shared language and chaos.

Your example makes the point: if `add_contact` let each implementer invent its
own relationship label — one says `professional`, another `coworker`, another
`employee` — no agent could reliably interpret another's contact. So the registry
classifies every schema field as one of two kinds:

- **Closed enum (canonical):** a fixed, registry-defined set of allowed values.
  Interop depends on it, so **all agents MUST use exactly these values on the
  wire.** Example — `add_contact.tier` ∈ `{ general, trusted, professional }`.
  You cannot invent `coworker`; you *propose* it to the registry (§6), and if
  accepted it becomes canonical for everyone. **This is the anti-chaos guarantee.**
- **Open field (free-form):** display/informational data with no interop meaning
  — a person's name, a free-text job title, a note. Any value is fine because no
  other agent branches on it.

**Wire value vs. display label.** The *canonical value* is what travels on the
wire (`professional`); the *label a UI shows* may be localized or rebranded
("Work contact", in another language) — presentation is free, the value is fixed.
So we get one universal vocabulary **and** flexible presentation, with no ambiguity.

Each registry entry therefore marks, per field: **kind** (closed-enum / open),
and for closed enums, the **canonical value set**. New enum values are added the
same way new codes are — proposed to the one registry, never minted privately.
That is exactly what prevents the fragmentation you flagged.

## 5. Reserved number ranges

| Range | Purpose | Assignment |
|---|---|---|
| `1 – 999` | **Core universal actions** — patterns most agents will support | By registry review (steward) |
| `1000 – 8999` | **Extended universal actions** — legitimate but narrower | By registry review |
| `9000 – 9999` | **Experimental / provisional** — may change or be withdrawn | Lightweight proposal |
| `≥ 100000` | **Private use** — vendor-internal, never interoperable, may collide | No registration; use at your own risk |

Private-use codes (`≥100000`) are the pressure valve: build whatever you want
privately without polluting the shared space. The moment you want *other* agents
to understand it, you promote it into the shared range via a proposal.

---

## 6. How to propose a new action code

Proposing is **permissionless**; *assignment* is canonical (one registry).

1. **Open a proposal** (an issue/PR against this registry) containing a filled-in
   registry entry (§4): name, summary, `request_schema`, `preview_contract`,
   `outcome`, and the motivating use case.
2. **Review** by the steward + open comment. Criteria (§8) checked:
   is it a *reusable* pattern? distinct from an existing code? clearly specified?
3. **Provisional assignment** in `9000–9999` for real-world trial (optional).
4. **Assignment** of a stable core/extended code once the schema is proven and
   at least one interoperable implementation exists.
5. **Publication** — the entry becomes canonical; the code is now immutable.

There is no gatekeeping on *who may propose*. There is a single authority on
*what a code means*, which is the whole point.

---

## 7. Versioning & compatibility

- **Codes are immutable.** `t=3` means `add_employee` forever.
- **Schemas evolve additively.** New optional fields are a minor bump; agents
  ignore unknown fields. Removing/retyping a field requires a **new code**.
- **Deprecation, not deletion.** A retired pattern is marked `deprecated` and its
  number is never reused.
- **Unknown codes degrade gracefully.** An Identity Agent that meets a code it doesn't
  implement still shows the generic Preview and can decline safely.

---

## 8. What qualifies as an action code

A pattern earns a shared code when it is:

- **Reusable** — multiple independent parties would issue or receive it (login,
  add contact, add employee, present credential, request payment, co-sign).
- **Interaction-shaped** — a request one agent makes that another fulfils by a
  consent → action, not an internal implementation detail.
- **Specifiable** — its data and outcome can be written down unambiguously.
- **Distinct** — not already covered by an existing code with optional fields.

Bespoke, single-party logic does **not** need a shared code — it lives in the
private-use range or inside an implementation.

---

## 9. Governance & stewardship

- **Initial steward: Grape ID**, as the party bringing the standard forward —
  the same way early internet standards had initial stewards before broadening.
- **Path to broadening:** as adoption grows, stewardship moves toward a neutral
  body / working group so no single vendor owns the shared language. The registry
  and framework are open source specifically to make this possible.
- **The steward's only power** is over the **number→meaning binding** (assignment,
  schema review, deprecation). The steward has **no power** over how anyone
  *implements* a code, and cannot revoke a published code.

---

## 10. The registered codes (human rendering of `registry.json`)

*Canonical data: [`identity-agent-core/actions/registry.json`](../identity-agent-core/actions/registry.json). Integer `code` (t) is the canonical wire identifier; `key` is the stable string handle (used as `?action=` in OOBI URLs and as `share_actions.action_key`).*

### `t = 1` · `login`
- **Summary:** authenticate to a relying party (website/app/device) with a pairwise identity.
- **Who mints:** the relying party (website).
- **Request schema (ChallengeBundle):** `site_aid`, `site_oobi`, `audience`, `nonce`,
  `dt`, `expiry`, `requested_disclosures[]`, `requested_credentials[]`,
  `requested_score?`, `callback_url`, `session_token`, `relationship_anchor_aid?`,
  `relationship_anchor_oobi?`.
- **Preview:** "Sign in to {site}" + what's being requested (data/credentials/score).
- **Outcome:** the agent presents a pairwise AID (per-RP by default; anchored to a
  chosen identity when `relationship_anchor_aid` is set), signs the challenge, and
  the RP verifies + optionally applies its access policy.
- **Notes:** `relationship_anchor_*` is a **general** mechanism — anchor the login
  relationship to a specified identity instead of a fresh per-RP one. (Grape uses
  it for employee-gated org portals, but the mechanism itself is universal.)

### `t = 2` · `add_contact`
- **Summary:** a mutual, front-facing "we know each other" contact ceremony between two agents.
- **Who mints:** a peer agent.
- **Preview:** "Add {name} as a contact."
- **Fields:** `tier` — **closed enum** `{ general, trusted, professional }` (canonical); relationship display name — open.
- **Tiers:** `general` · `trusted` · `professional` (the relationship strength the user grants).
- **Outcome:** each side records the other as a contact at the chosen tier (distinct
  from low-level transactional KERI contacts, which are automatic and unceremonious).

### `t = 3` · `add_employee`
- **Summary:** an organization invites an individual to become an employee; the
  individual's agent presents a stable per-org pairwise identity to be enrolled.
- **Who mints:** an organization.
- **Request schema:** `org_name`, `org_aid`, `org_oobi`, `site_aid`, `site_oobi`,
  `role`, `invite_token`.
- **Preview:** "Join {org} as {role}."
- **Outcome:** the individual derives/reuses a stable pairwise AID for the org and
  is added to the org's roster (pending → active on approval). The *code + schema
  are universal*; the roster/approval mechanics are an implementation concern.

### `t = 4` · `sign_org`
- **Summary:** an individual attests (vouches) that a real person stands behind a
  newly created organization, becoming its founding super-admin. These
  individuals are **signers** — they sign an organization into existence.
- **Who mints:** an organization (during creation).
- **Request schema:** `org_name`, `org_aid`, `org_oobi`, `site_aid`, `site_oobi`,
  `invite_token`.
- **Preview:** "Sign {org} into existence — become its super-admin and first
  member."
- **Outcome:** the individual signs a vouch over the org's AID (stored by the org
  as proof) and is enrolled as the active super-admin. No delegated inception —
  the org controls its own keys; the signer only attests.

---

## 11. What is open vs. proprietary (for implementers)

- **Open (this registry + the framework):** the Ask envelope, the scan pipeline,
  the preview contract, the **action codes and their schemas**, and any reference
  implementations contributed to the OSS core.
- **May be proprietary (an implementer's choice):** the *rich implementation* of
  either side of an action — e.g. a roster, approval flows, access policy, scoring,
  hosted services, and product UX. This holds for any party on any side; for
  example, Grape ID keeps its own organization-side execution proprietary while the
  *codes it speaks* stay open. The registry never requires an implementation to be
  open — only that whatever you build speaks the canonical codes + schemas.

A conforming Identity Agent is one that reads the open envelope, honours the registered
schemas, and renders faithful Previews. Everything past "the user approved" is
yours to build.
