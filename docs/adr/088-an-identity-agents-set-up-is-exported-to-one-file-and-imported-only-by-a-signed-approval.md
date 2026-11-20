# ADR-088: An Identity Agent's Set-Up Is Exported to One File and Imported Only by a Signed Approval

**Status:** Proposed (2026-11-20)
**Date:** 2026-11-20
**Deciders:** Rob Andersen
**Amends:** ADR-045 ("Who authorised it", rules 4, 5 and 7), by decision 8: one signed approval authorises each item of the list it names. The amendment's own text, and the change to the grant check, are ADR-045 Amendment 5, which is a separate change. Nothing issues a grant from an approval until it lands.
**Builds on:** ADR-021 (the Ask), ADR-041 Amendment 1 (a computer asks by a short pointer, not a dense code), ADR-042 (how an Identity Agent is reached, and the signed request), ADR-044 (an authorised controller does the work, the owner's key is the root of trust), ADR-045 (every asset gets an identity and a grant), ADR-047 (AI agents talk through the Identity Agent that holds them), ADR-050 (one check for a controller's actions and an AI agent's capability calls), ADR-056 (revoking an AI agent is final), ADR-057 (an API key stays with the Identity Agent), ADR-072 (a utility app), ADR-080 (a person signs a statement with their own Identity Agent)

---

## Context

An organisation's Identity Agent holds a set-up: the AI agents it made, the utility apps and websites it serves, what each may do, the limits on that, and how each is configured. Today that set-up is built one screen at a time and exists in one place. It cannot be copied to a second Identity Agent, kept as a template, reviewed as a whole, or rebuilt after a loss, except by hand.

A file solves that, and a file is also dangerous. Whoever writes a file chooses its contents. If importing a file made things exist, a file would be a way to grant authority without the owner deciding anything.

So this record decides two things together: what the file is, and that a file can only ever **propose**.

**What could go wrong, and what answers it.**

- **A file grants more than the owner noticed.** Every permission is shown. The ones the importing Identity Agent marks as needing care are acknowledged one by one, and the acknowledgement is inside what is signed (decisions 7 and 10).
- **Something imported starts running with nobody having looked.** It cannot: it is created needing set-up (decision 9).
- **A file impersonates or overwrites something that exists.** A name already in use is never overwritten. An imported name is compared with the names already held by the file's own folded form, so a fullwidth or bold spelling of a name in use, or one that differs by an unseen joiner, is that name and not a second thing that reads the same (decision 11).
- **A name is bound to the wrong thing.** Every name the signed list relies on is bound in it to one thing, never to whatever has the name later (decision 7).
- **Text in the file is an attack on an AI agent.** Text from a file is shown to the person as text from a file. It is never shown to, or summarised by, an AI agent on the way to the approval (decision 6).
- **A secret leaks into a file.** An exporter never reads one into a file, and an importer refuses a file that holds a key or a token (decisions 2 and 4).
- **A file is used to write into a log or onto a screen.** Nothing a reader says repeats text from the file (decision 1).
- **An approval is replayed, or the list is swapped after it was read.** The approval is over the exact bytes of the chosen list, which name the Identity Agent, the proposal and a nonce, and it is used once (decisions 7 and 8).
- **One item of many fails.** The others stand, and importing the file again offers only what is missing (decision 12).

**Threat boundary** (a proposal, see the last section). The attacker can write any file and hand it to the owner, and can alter a file in transit. The attacker does not hold the owner's key or the key of a computer the owner authorised. A compromised owner device is out of scope. A compromised authorised computer is not prevented by this record: decision 8 says what contains it.

## Decision

### The file

1. **One JSON file, `identity-agent-set-up/1`.** Its fields, limits and rules are in [docs/set-up-file.md](../set-up-file.md), with vectors; that document is the format and this record does not repeat it. The rules a reader follows:
   - A file of a higher major version is refused whole.
   - An item of a kind the reader does not know is listed as not understood and skipped, in plain sight.
   - A field the reader does not know, in an item of a kind it does know, blocks that item.
   - A member of the file itself that the reader does not know refuses the file.
   - Nothing is dropped silently. A reader either accounts for a thing or says it could not.
   - Nothing a reader says repeats text from the file. It says where, by the format's own words and by position, and never what.

   The version changes only when a version-1 reader would misread a file. A new kind, or a new extension, is not a new version: a version-1 reader lists the first and blocks an item carrying the second.

2. **What an item holds, and what a file never holds.**
   - Every item holds its kind and its name. It may hold permissions, limits on them, and when its grant ends. Everything else belongs to its kind.
   - A file never holds: a key, a seed, a token, or a digest of one; the identifier of an asset, a grant, a machine or a controller; members, employees or invites; conversations, activity or anything an AI agent remembered; anything revoked; or any setting that is the owner's alone (owners, signers, controllers, witnesses, recovery). Those are set by hand, by the owner, on purpose.
   - **Secrets are named, never carried.** A credential (a model sign-in, a service's key) appears only by name, in the file's list of credentials the importer will need. The secret stays in the exporting Identity Agent (ADR-057).
   - **References are by name.** A permission on a utility app names the utility app, not its identifier. The exporting organisation's own identifier is written `self`. An identifier of something outside the Identity Agent (a repository, a DNS zone, another identity) stays as it is and is flagged, because the importing organisation needs its own access to that thing. An exporter that cannot turn an identifier into a name does not write the item, and says so.
   - **A name may be spelt as its language spells it.** A reader does not refuse ordinary writing.

3. **A file may carry a seal, and a seal proves one thing.** A seal is the exporting Identity Agent's signature over the file's contents, in the statement signature envelope of ADR-080, used as "A statement made unasked" in `docs/statement-signature.md` says. A seal that holds proves that these contents left that Identity Agent as they are now. It proves nothing else:
   - It gives nothing in the file any authority.
   - It does not say the contents are right, safe or wanted.
   - It is not required. A person may edit a file before importing it, and may write one by hand.

   **A seal is found to be one of six things**, and the review says which, in these words or their like:

   | Found | Shown as |
   |---|---|
   | No seal | "Not sealed." |
   | Sealed: the signature verifies under the sealer's key in force, over these contents | "Sealed by" the sealer, "and unchanged since." |
   | Sealed by an earlier key: it verifies over these contents, under a key the sealer has since replaced | "Sealed by" the sealer "with a key it no longer uses." Never as sealed. |
   | A seal made for other contents: the signature verifies, over a digest that is not this file's | "Carries a seal made for other contents." Nobody is named. |
   | Broken: the signature does not verify | "Carries a seal that does not verify." Nobody is named. |
   | Unchecked: the sealer's key could not be found | "Carries a seal that could not be checked." Nobody is named. |

   - **A sealer is named only when its seal holds over these contents.** A genuine seal can be copied from one file onto another, so a seal made for other contents puts nobody's name on this file: its sealer may never have seen it.
   - **The signature is checked before the contents are compared**, and against the key the sealer's own key log names. So a seal anybody wrote in somebody else's name is broken.
   - **Who can make one:** only the device that holds the identity's key. An Identity Agent whose key is on another device exports unsealed, unless that device signs. An identity with more than one key does not seal in version 1.
   - **A seal is a signature, and is not anchored in the exporter's key log** in this version. An anchored digest would survive the exporter's key rotations, where a signature made by a replaced key can only be reported as that. Nobody relies on a seal for authority, so the cheaper thing is enough here.

   **Nobody vouches for the contents of a file.** The importing owner reads the list and an approval is signed, and that is the only authority there is.

### Export

4. **Export is one request, and it adds no signature of its own.**
   - **Who may ask:** the owner, or a computer the owner authorised to act for the identity (ADR-044). An AI agent's token, a utility app's back end and a browser session may not.
   - **No extra signature.** An export reveals nothing such a computer cannot already read item by item, and it reveals no secret. It passes the one check every such request passes (ADR-050).
   - **It is recorded:** one entry in the Identity Agent's activity log, with the file's digest.
   - **An exporter keeps secrets out by never reading one in.** It writes names and settings. As a floor under that, every piece of free text is checked for the spellings of a secret before it is written, and an item that fails is left out, with the export saying which item and why. The spellings are a closed, published list, so a file is never refused by an importer for a reason its exporter could not have known. The check is a floor and not a guarantee.

### Import

5. **An import is a kept proposal.** A file handed to an Identity Agent is parsed, checked, and kept as a **proposal**: a list of items, each one a creation, a change or a removal. Nothing in a proposal has happened. **This version performs creations only.** The model carries changes and removals so that they need no second design, and a request to perform either is refused in words that say it is not built.

6. **The owner reviews the proposal.** Each item is shown as one of: new; already here and the same; here but different; or blocked, with every reason. Items not understood are listed. Text from the file is shown as text from the file, in full, and is never passed to an AI agent to read, summarise or act on before the approval.

7. **The owner chooses, and the choice is fixed as exact bytes.** The owner picks items, acknowledges each permission that needs it (decision 10), says which utility app each name means, and maps each needed credential to one the importing Identity Agent stores, or leaves it to enter afterwards. The Identity Agent then fixes the **chosen list** and gives it canonical bytes. The list holds:
   - the importing Identity Agent, the proposal, and a nonce;
   - the digest of the source file, and what its seal was found to be. This is taken only from the file and the check of its seal, never written by hand;
   - for each chosen item: its place in the file, its operation, kind, name, permissions, limits and grant end in full, a digest of every other field, the permissions acknowledged, and the utility apps its own fields name;
   - for each utility app the list names, in a permission or in a field: that it is an item of this same list, or the utility app the importing Identity Agent already has, by its identifier there;
   - the credential mapping.

   One choice has one list: the items in the file's order, each item's acknowledgements in the order of its permissions. A choice that names one thing twice gives no list.

8. **One signed approval over those bytes authorises each item the list names, and nothing else does.**
   - **What is signed** is the signed-request form the Identity Agent already takes (ADR-042), with the chosen list as the body. The form names the Identity Agent, the route, the time and the digest of the body, so the signature covers every byte of the list. **There is no new signing format.**
   - **One approval, each item once.** The approver signs what they read, which is one list. Each grant issued carries that approval and says which item of the list it is. This amends ADR-045's "Who authorised it": rule 7 ("one request authorises one credential") becomes one request authorises one credential, **or each item of the one list it signs, once each**; rule 4 ("what was issued is what was asked") is read against that credential's item of the list; and rule 5 (the body's digest, and `asked`) is read against the whole list as the body, with the item named. ADR-045 Amendment 5 carries that text and the change to the grant check. Until it lands, nothing issues a grant from an approval.
   - **The Identity Agent builds the bytes itself** from the kept proposal and the recorded choice, and refuses an approval over anything else. It never acts on a list the approver sent, and what it applies is what the approved bytes say.
   - It checks the present state again at that moment (a name may have been taken since the review), and an approval is used once.
   - **The first version is approved at an authorised computer, and that is the computer's signature, not the owner's.** The computer signs with its own key, under the grant the owner gave it to act for the identity (ADR-044), and the request passes the one check (ADR-050). **No owner key signs the list in this case.** That is what every screen action at such a computer is today. An import adds two things beyond those screens:
     - many creations ride on one request;
     - the record afterwards reads as a considered approval, with acknowledgements, although a program on that computer could have ticked them itself.

     Two rules contain that:
     1. **Each item passes the same check its own route would**, with the same grant, limits and level of authentication. One request for forty items can do nothing forty requests could not.
     2. **A kind whose own route is owner-only is not created by a computer's approval.** Such an item waits for the owner's key.
   - **Approval by scanning, with the owner's own key, follows.** The computer shows a short pointer, as ADR-041 Amendment 1 defines one. The owner's device follows it, fetches the chosen list from the Identity Agent, checks its digest against the one the pointer's Ask carries, and reads the list strictly. The list carries each item's other fields only as a digest, so the device fetches those too and checks each against that digest before it shows them. It shows the items that need care first, and signs with the owner's key. A list of forty items never travels in a code. Both ways sign the same list.
   - **When the identity's key is on another device** (ADR-044 as amended), a delegated identity is approved by the device that holds the key. An import does not change that: each imported asset that gets a delegated identity **waits for that device to approve its identity**, one at a time, as an asset made by hand does, and is listed as waiting until it does. The approval of the chosen list does not stand in for it.

9. **What is imported is made new, and is made needing set-up.**
   - **Nothing signed elsewhere carries over.** Each imported asset gets a new identity from the importing organisation, and each one that asks for permissions a new grant, exactly as if it had been made by hand (ADR-045). A website is signed in to and holds no grant. No credential, signature, key log or token from the exporting Identity Agent is honoured, copied or referred to.
   - **Set up needed.** An imported asset that would run is created in states its owner must complete:
     - it has **no machine**;
     - **no token** has been handed to anybody;
     - its **model sign-in is unresolved** unless the owner mapped it to a stored credential in the chosen list;
     - its **identity is waiting for approval** where the identity's key is on another device (decision 8).

     So an import never yields something running that nobody looked at.
   - Revoking stays final (ADR-056). A file never holds anything revoked, and an import never brings a revoked AI agent back.

10. **Some permissions need an express acknowledgement, inside the signed list.** The importing Identity Agent, and any add-on that defines permissions, says which permissions need one: for example making AI agents, providing machines, writing or approving code, changing DNS. Such a permission is listed first and is not ticked for the owner. The acknowledgements are part of the chosen list, so they are signed, and there is no way to make the list's bytes that skips the check. A permission the importing Identity Agent does not know blocks its item.

11. **An existing name is never overwritten, and nothing is created that reads the same as something here.**
    - Two names are one name when they are the same letters, whatever their case and however they are spelt (fullwidth, bold, a ligature, a joiner more or fewer). The format document gives the exact form, and `setupfile.SameName` is it.
    - Among the items of a file, no two have one name.
    - **An import compares an imported name with the names an Identity Agent already holds by that same form, in addition to the kind's own rule.** The core's own comparison (the names of AI agents and of utility apps, trimmed and without case; a website by its origin) takes a fullwidth spelling of a name in use for a different name. The import does not: a match by either rule is shown as already here, and creating it is not offered.
    - Whether a name that belonged to something revoked stays taken is not decided here.

12. **Importing twice is safe, and a failure is partial.**
    - **Idempotent.** Importing the same file again proposes only what is missing: an item that is already here and the same is shown as that.
    - **Partial failure.** Items are applied one at a time. If one fails, the ones before it stand, later ones that do not depend on it continue, and one that depended on it says so. The work survives a restart.
    - **Proof afterwards.** The Identity Agent's activity log holds the proposal, the approval with its exact bytes, and one entry per item linked to the approval. Each grant issued carries the approval it rests on and names its item of the list (decision 8).

### The kinds, and what an add-on adds

13. **A proposal from an AI agent uses this same path.** When an AI agent is later allowed to propose a change to the set-up, its proposal is the same kept list, awaiting the same review and the same signed approval, with the same record. Only the source differs. What that adds is decided when it is built: who may propose, the proposer's own signature on what it proposed, a limit on how often, and that a proposer reads back only the outcome, never a secret and never the approval.

14. **The format itself defines a website, an AI agent and a utility app.** These are the three things the core's own asset model holds (ADR-045, ADR-047, ADR-072), so a file exported by one maker's Identity Agent is read by another's for exactly what ADR-045 standardises.
    - Each is a kind written as one word: `website`, `ai_agent`, `utility_app`. Their fields are the fields the public core already holds for each, and nothing an add-on alone knows.
    - **An add-on's own data rides in an extension**, under a namespace it owns: what an add-on alone knows about an AI agent is carried on the `ai_agent` item, not in a kind of its own.
    - **This change publishes `website` and reserves the other two.** The fields of `ai_agent` and `utility_app` are published, and the reader reads them, in the change that follows. Until then a file that holds either is read as any file with a kind this version does not yet understand: the item is listed and skipped in plain sight, never dropped.
    - A kind of anybody else's carries its maker's namespace. One word is the format's alone.
    - **A name of a utility app resolves only to a utility app**: a utility-app item of the file, or one the importing Identity Agent already has. An item of another kind with the same name is not it.
    - The reader's rules hold for every kind and extension, whoever wrote it: an unknown field blocks, a secret refuses the file, a name is a name. A kind an add-on adds says nothing in its own words: it gives a code it declared and a place, and the reader shows the sentence declared for it.

15. **Which part is public contract.** Another party receives this file and must be able to read it, so these are open, with vectors and an independent checker:
    - the file format and the strict reader;
    - the seal, and how it is checked;
    - the proposal, the chosen list and its canonical bytes;
    - the registry through which a kind or an extension is added;
    - the Unicode facts text is judged by, pinned in one published file.

    The code that builds an export from an add-on's own stores, and the code that applies an add-on's extension, belong to the add-on. An extension's format is published here when another party needs to read it.

## Relationships, and who proves each

Every relationship this feature creates or relies on, who asserts it, and who proves it.

| Relationship | Who asserts it | Who proves it | What relies on it |
|---|---|---|---|
| **Exporter and file** | The exporting Identity Agent, by its seal | **One side: the exporter.** Nothing more is needed, because nothing relies on the seal for authority. A seal only tells the reviewing owner whether these contents are the ones that left. | The words on the review screen. Never whether an item may be created. |
| **File and importer** | Nobody. The file names no importer and the importer takes nothing from the file on trust. | **The importing side alone,** by the signed approval of the chosen list. | Everything that is created. |
| **Authorised computer and owner** | The computer, by signing the approval request with its own key | **Both sides.** The owner issued that computer a grant to act for the identity (ADR-044), and the computer's key signs each request. What is proved is that *this computer* approved, under the owner's standing grant. It is not proved that the owner read this list: no owner key signed it. | Approval at an authorised computer (decision 8), within what that computer could already do item by item. |
| **Owner and list** (by scanning) | The owner, by signing the chosen list with their own key | **One side is the whole of it:** the owner's key, over the exact bytes. | Approval by scanning, and any item a computer may not create. |
| **Proposer and owner** (later, decision 13) | The proposing AI agent, by signing what it proposed | **Both sides.** The proposer signs its proposal. The approval is signed. Both are kept. | That a proposal came from the AI agent it names, and that it was agreed to. |
| **Imported asset and organisation** | The organisation, by naming itself the asset's delegator | **Both sides,** by the mechanism ADR-045 already uses: the asset's delegated inception names the organisation, the organisation's own key log approves it, and the organisation issues the grant. Where the key is on another device, that device approves each one. | Everything the imported asset is later allowed to do. |
| **An item and the utility app it names** | The file, by a name in a permission or in a field | **The importing side, in the signed list.** A name proves nothing: the list says whether it means an item of the same list, or which existing utility app by its identifier there. One side is enough because both the item and the utility app belong to the importing organisation. | What the item may do on a utility app, and on which one. |
| **A website and the issuer it requires** | The file, by an identifier (or `self`) in the website's policy | **Nobody, by the import.** The file names an issuer; that issuer agrees to nothing and is asked nothing. It is flagged for the owner, who chooses it by approving the item. The proof comes later and elsewhere: a credential a person presents at sign-in is checked against that issuer's own key log. | Who may sign in to the website. Never anything the issuer is taken to have promised. |
| **Credential reference and stored credential** | The owner, by mapping a name in the file to a credential the Identity Agent stores | **One side is enough,** because there is one party: both the name and the stored credential are inside one Identity Agent, and the mapping is inside the signed list. A name in a file never selects a credential by itself. | Which stored credential an imported asset may use. |

Two things follow. A file that names an identifier, an owner or an issuer proves nothing about that party. And a name that matches is never an agreement: a credential is used because it was mapped, and a utility app is meant because the signed list says which.

## Consequences

- **A reader is strict on purpose, and that costs convenience.** A file with one stray field has one blocked item. A file with a token pasted into a note is refused. The alternative is a reader that guesses, and a guess is how a file ends up meaning two things.
- **A new field is not backward compatible for the item that carries it.** An older reader blocks that item. This is intended: an older reader that dropped the field would create something other than what was exported.
- **An export is not a backup.** It holds no keys, no members and no history. It rebuilds what a set-up *is*, not what an Identity Agent *has done*.
- **An import does not finish the work.** Machines, tokens, unresolved sign-ins and identities waiting for another device remain for the owner, by design.
- **No owner key signs an import until approval by scanning is built.** Until then an import is approved by a computer the owner authorised, within the two rules of decision 8.
- **Nothing issues a grant from an approval until ADR-045 Amendment 5 lands.** This record adds no route, so that is true of the code as it stands.
- **The rules of thumb for a secret will catch some text that is not one.** They block one item and never the file, and say where. The spellings that refuse a file are a closed list.
- **The look-alike rule for names is modest.** It catches one borrowed letter in a word. It does not catch every look-alike, and it is not what protects a grant: the binding in the signed list is.
- This record adds no route and no store. The package `identity-agent-core/setupfile` holds the format, the reader, the seal's check and the chosen list's bytes as pure functions, with `set-up-file-vectors.json` and an independent checker. The fields of an AI agent and of a utility app, ADR-045 Amendment 5, the export, the proposal store, the approval and the record follow, each as its own change. The refusal, in the handler that answers an Ask, of a statement made unasked (`docs/statement-signature.md`) is one of those changes.

## Is this the permanent answer?

- **Not a stopgap.** Authority comes only from a signature over exact bytes by a key the owner controls or granted, recorded. Nothing is trusted because a file says so.
- **The protocol already had the parts.** Identities and grants (ADR-045), the signed request and the one check (ADR-042, ADR-044, ADR-050), the Ask and its short pointer (ADR-021, ADR-041), the statement signature envelope (ADR-080), and the activity log.
- **Standard mechanisms.** The canonical bytes are JSON in the JSON Canonicalization Scheme (RFC 8785). Digests are Blake3-256 in CESR. Signatures are Ed25519 in CESR. Names are held to Unicode Normalization Form C and compared in Form KC with simple case folding, and joiners are allowed where Unicode's identifier rules allow them (UAX #31), all from the Unicode Character Database's own data files. No new signature format, envelope or canonical form is introduced.
- **Where it is not yet the permanent answer.** The seal is a signature, and the permanent form of "this identity published this" is a digest anchored in its key log (decision 3 says why that is not done here). Approval by the owner's own key follows the first version.
- **Not verified.** The ACDC specification describes bulk-issued credentials. Whether that mechanism fits one approval for many grants, in place of a new field in a credential's request block, was not checked. ADR-045 Amendment 5 is where it is checked, before a field is invented.
- **What it rests on.** A person reading the list. The design puts what matters first and makes the dangerous parts impossible to approve without acknowledging them, and it still rests on a person reading.

## Alternatives rejected

- **A sealed file is imported without review, because its exporter is trusted.** A seal says where bytes came from. It cannot say they are wanted here, and the importing organisation has agreed to nothing.
- **A file carries the exported credentials and grants, to be re-homed.** A grant is one issuer's statement about one identity. Carried elsewhere it is either meaningless or a way to claim authority nobody here gave.
- **A file carries secrets, encrypted.** Then the file is as sensitive as the Identity Agent, and its safety is the strength of a passphrase somebody typed.
- **A lenient reader that ignores what it does not know.** It makes an older reader create less, or other, than was exported, without saying so.
- **A new signature format for the approval.** The signed request already covers a body by its digest.
- **A second envelope for the seal.** The statement signature envelope already says "this identity signed this text", and a second one would be a second thing to get wrong.
- **Overwrite an existing item when the names match.** A file would then be able to change what something in use may do, under a name the owner already trusts.
- **Bind a name of a utility app when the list is applied.** Whatever had the name at that moment would be what the owner is taken to have meant.
- **One signed request for each item.** It needs no amendment of ADR-045. It turns one decision into many prompts, no single signature covers the list as a whole, and forty signatures are forty chances to approve something without reading it.
- **Leave an AI agent and a utility app to add-ons.** Then every maker defines "an AI agent" in its own namespace, and two makers' files carry websites between them and nothing else.
- **Wait for approval by scanning before any import.** It delays a working import for a second way to approve the same bytes.
- **A table of look-alike characters for names.** It is large, it moves with every Unicode version, and it would still not be what protects a grant.

## Starting values and rules proposed here

The decisions above are taken, and this record becomes Accepted in a later change. Much else was chosen while writing the format and its reader, so that there would be something exact to test, and **has been decided by nobody**. Each of these is a proposal:

- **The threat boundary** stated in the Context.
- **Every size and count**, and every rule of strictness: an unknown member of the file refusing the whole file, no minor version, no null, a seal that is not written as one refusing the file, whole numbers only, one spelling of a time and of an origin.
- **The secret and identifier rules:** the closed list of spellings that refuse a file, the rules of thumb that block an item, and what is flagged in prose.
- **The name and text rules:** Normalization Form C for a name, the exact folded form by which two names are one, no word that mixes Latin, Greek and Cyrillic, where a joiner and a variation selector are allowed in a name and where else in text, what else text may hold and what it may not (the bidirectional marks, and the thin, figure and em spaces), and the pinned Unicode version.
- **Names already in use:** that a revoked name's fate is left open.
- **What a reader says:** places by position, and a kind saying only what it declared.
- **The shapes:** a permission on a utility app, how a kind is named, `extensions`, the flags, a second website of one origin.
- **The seal's form:** its members, the envelope and the signer on the asker line, the key event inside the signed statement, the six states and their order, that only a seal over these contents names a sealer, and that an identity with several keys does not seal.
- **A statement made unasked:** the two refusals `docs/statement-signature.md` asks of whatever answers an Ask.
- **The chosen list's form:** its members and bounds, the binding of utility apps and credentials, the one order it is built in, and that it has no rename.
- **That an import keeps the per-asset approval** where the identity's key is on another device (decision 8).

The full list, with each value, is at the end of [docs/set-up-file.md](../set-up-file.md).
