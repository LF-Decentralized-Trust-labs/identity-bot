# ADR-068: A Conversation's Trail Keeps Who Said What, Never the Words

**Status:** Proposed
**Date:** 2026-11-06
**Deciders:** Rob Andersen
**Builds on:** ADR-067 (a person signs a salted fingerprint of their words, not the words)
**Extends:** ADR-047 (AI agents talk through the Identity Agent that holds them) — its countersigned, chained conversation record, which this ADR makes the trail rather than sitting beside it
**Amended:** 2026-11-10 — what keeps the trail is an add-on's, not the core's (see "Where the store lives", below)

---

## Where the store lives

Not every Identity Agent keeps a conversation's trail, so the code that keeps
it is not in this repository. The **format** and the **checks** are, because
others need them to build against and to verify what they are given:

- the signed-fingerprint format and its vectors (ADR-067);
- the entry format: the chain's records (`agentmessage.Record`), with the
  person's statement, refusal and outcome entries this ADR defines, and the
  contract that describes them (`identity-agent-core/contracts/trail`);
- the offline checker of a conversation (`conversationbundle.Verify`);
- the one check that a person's statement is the person's and was signed in
  time (`trail.CheckAuthor`, `trail.CheckFresh`, with `trail.KeyRoster` and
  `trail.Write`), which the core runs at the door for an app speaking for a
  person, and which every store runs first on every write;
- the limits that protect the core (`limits.Limits`, `AppLimits`), including
  the numbers a store of conversations is held to.

The **store** (`Trail`: the conversations in memory, the rules of steps 4 to 6
below, the forwarding to the app, `Read`, `ReadPage`, `AppendAgent`, and the
not-delivered mark) belongs to an add-on kept outside this repository. An
Identity Agent that includes such an add-on still keeps the trail of
fingerprints while the app keeps the words. Where this ADR names `Trail.*`
below, it names that store. Nothing about what the store does has changed, only
where it lives.

## One record, not two

ADR-067 defines what is *signed*: the fingerprint and the person's statement.
This ADR defines what the Identity Agent *keeps* and the order in which it
keeps it. It does not keep it in a record of its own. **A conversation already
has one chain**: ADR-047's countersigned entries (`agentmessage.Record`, hashed
by `agentmessage.Hash`), checked offline by `conversationbundle.Verify`. The
trail is that chain, extended with the entries below. There is no second chain
and no second verifier, so one conversation never has two heads to disagree.

ADR-067 says these rules "land with the work that uses this format"; this is
that work.

## Context

An app can keep the words of a conversation while the Identity Agent keeps the
record of who said what, in what order, signed. Two things must then hold: the
Identity Agent decides what may be written from its own record alone, and an
app that is broken into, or down, cannot make anybody see, or be told, a
conversation that did not happen.

## Decision

### The trail

For each conversation the Identity Agent keeps its opener, its owner, whether
it is open or closed, every hand-off with who made it, and **the chain**: the
ordered, countersigned entries of ADR-047's record. Four things are entries of
it, and **none holds words, a salt or a preview**:

- **A person's entry.** A record whose sender's proof is the person's
  statement (ADR-067), the key that signed it and the signature
  (`person_proof`), in place of the signed request of a paired app. The
  statement holds the fingerprint, the kind, the recipient, the sender's message
  id and the nonce, so all are inside what the author signed. The record's id is
  `e` and its place in the chain (`e1`, `e3`…): the id the app keeps the words
  under. For an entry the Identity Agent holds only as ciphertext, it also
  carries `ciphertext_hash`, which is the statement's fingerprint.
- **A refusal.** The same record with `refusal` set to the reason. It records who
  tried, when and why.
- **An outcome.** A record of kind `outcome`, from the Identity Agent, saying
  how an earlier entry ended (`committed`, or `not-kept` with a reason). It
  carries no sender's proof; its countersignature is the proof.
- **An AI agent's entry.** The record ADR-047 already makes: countersigned by the
  AI agent, in the same chain, **committed by being countersigned**. The trail
  takes it in at the head of the chain (`Trail.AppendAgent`) without forwarding
  it, and the rules below do not apply to it: ADR-047's do. Its statement
  (`IA-AGENT-MSG-V1/V2`) does not name a fingerprint version yet, so it keeps
  the unsalted `body_hash`, and it is not counted by the version rule (below). Moving an
  AI agent's words to salted fingerprints, its hand-off and the turn limit
  are a later change.

An entry is never changed. A person's entry is **pending** until an outcome
entry follows it; a refusal never has one. The state of an entry is therefore
read from the chain itself.

### Four states

| State | Meaning |
|---|---|
| **pending** | allowed, forwarded to the app, not yet confirmed |
| **committed** | the app confirmed it kept the words, repeating the fingerprint of what it stored, and that equals the statement's |
| **not kept** | the app refused, confirmed a different fingerprint, or did not answer within the forwarding timeout; the sender is told and the app is told to discard the words |
| **refused** | the Identity Agent refused the write before forwarding anything; the entry records who tried, when and why |

Only a **committed** entry is delivered, read or counted as part of the
conversation. A person is told a message was sent only once it is committed.
A retry after *not kept* is a new entry with a new id and a new nonce.

### The order of a write

1. **Prove an author.** The statement must be well formed, name this Identity
   Agent (ADR-067), its signature must be its signer's, and the Identity Agent's own records must say that key
   speaks for the person. If not, nothing joins the trail: nobody can be
   recorded as having tried. The caller's governance record says it happened.
2. **An id already seen** (scoped to the conversation and the author): the same
   statement and signature returns the earlier result, whatever state it is in;
   any difference is refused, "id already used". This comes before the rules, so
   a retry after a lost reply gets its answer even when the conversation has
   moved on. A given different statement is recorded as a refusal once.
3. **A nonce already used** by the author in the conversation is refused.
4. **The rules,** decided from the trail and the Identity Agent's roster only,
   never from a value the app sends: the words and salt match the signed
   fingerprint; a message answers a committed entry of this conversation; only
   the owner writes, closes or reopens; a closed conversation takes only a
   reopen; a message is addressed to an AI agent the writer may use; a hand-off
   is made by the owner or a signer; a hand-off's or a split's new owner is an
   AI agent the writer may use or an active employee; a split names a range of
   committed entries of this conversation.
5. **A refusal** from step 2, 3 or 4 joins the trail as a wordless refusal.
   Nothing reaches the app. **While the app cannot be reached,** a write is
   refused with a plain reason.
6. **Otherwise** the entry joins the trail pending and is forwarded with its
   words and salt, which the Identity Agent holds only in passing. If the app's
   confirmation matches, the entry is committed and its effect (a new owner, a
   close, a reopen) takes hold; otherwise it is not kept and the effect never
   happens.

A conversation's writes are taken one at a time, so two retries of one id
cannot both be forwarded.

### The chain

Each entry carries the hash of the one before it, exactly as ADR-047 has it:
`agentmessage.Hash` over the countersigned entry and its signatures. The
Identity Agent records the latest entry's hash, the **head**, in its key history
(a later change), which is what catches a cut-off end. Because an outcome is an
entry of its own, nothing already in the chain is rewritten to say how an entry
ended, and nothing can be slipped in, reordered, removed or have a refusal's
reason rewritten unnoticed.

### Offline verification

`conversationbundle.Verify` is the only verifier. For a person's statement entry
it checks that the statement is signed by the key it names, names the Identity
Agent that holds the conversation, and is dated within the stated skew of the
Identity Agent's stamp; that the record says what was signed; that an entry
which answers another answers one that was kept at that point; that an entry the
Identity Agent allowed does not reuse an id or a nonce its author used before (a
refusal may, and uses them up); that an outcome is the Identity Agent's, is about
an earlier entry that was pending, and ends it once; and that the entry's id is
its place in the chain. **A kept entry, a not-kept entry and a refusal verify
alike**, since each keeps its fingerprint and signature and none keeps words.
With the words and salts an app exports (`body` and `salt` of the bundle's
entry), a reader also recomputes every kept entry's fingerprint; words offered
for an entry that was refused or not kept are a fault; words left out are listed
as something the check could not rule out. The bundle format refuses a field it
does not know, since it has nowhere to carry words.

**The cut-over (ADR-067).** A person's words are version 0 when they are in the
signed request of a paired app (ADR-047), which holds them unsalted, and version
1 when they are a statement's fingerprint. `conversationbundle.Verify` faults a
version 0 entry that follows a version 1 entry of the same conversation
(`agentmessage.CheckVersionOrder`, tried on the published genuine export's own
records). An AI agent's entry and an outcome are not a person's words and are not
counted.

What the offline check cannot show, it says: which person a device's or session's
key speaks for, and whether the Identity Agent's rules allowed a write, are the
Identity Agent's word.

## What this ADR does not do

- It does not change how an **AI agent's** entries are made or checked (the host
  statement, the Identity Agent's countersignature over `body_hash`, the turn
  limit, an agent's onward ask). They are in the same chain, as above. Salting
  them needs the agent's statement to name its fingerprint version, which
  `IA-AGENT-MSG-V1/V2` does not yet; a later change.
- It does not store the chain durably, record the head in the key history, or
  rate-limit. The store (the add-on's) keeps the chain in
  memory behind the rules above and below; the Identity Agent's table and routes
  use it.

## A message id is used up by a refusal

A refusal takes the sender's message id and nonce. A message refused only
because the app could not be reached is therefore **not retried under the same
id**: the same statement returns the same refusal, whatever the app's state
now, so the sender **resends it under a new message id** (and a new nonce, and
so a new statement and signature). The same holds for any other refusal whose
cause has passed. A message that was *not kept* is the same: a retry is a new
entry with a new id.

## Reads and `@agent`

- **An `@agent` needs two yeses.** An AI agent may be addressed only if its own
  grant allows the person and the reach of the person who started the turn
  includes it (`Roster.AgentGrantAllows`, `Roster.MayUseAgent`). An onward ask
  uses the turn starter's reach, found by following what each entry answers
  (`Trail.TurnStarter`, `Trail.MayAddress`), never the asking agent's.
- **Who may read** is decided from the trail and the roster: the opener, the
  current owner, and a signer. A former owner loses access when they hand the
  conversation on; having written, been addressed or been named in a hand-off
  admits nobody. An AI agent addressed with `@agent` is therefore refused by
  `Trail.Read`: reading only the thread it was asked in is a later, separate
  read. Nothing the app says is used.
- **`Trail.Read` serves a person's entries only.** An AI agent's entries are
  in the chain but not in the read: words the app returns for one are refused
  as an entry the trail lacks, and a range bounded by one is refused. Reading
  them is left to the part that adds the agent's thread.
- **A write is held to the verifier's two rules about a refusal and time.**
  Every refusal, an id-reuse refusal included, uses up its author's id and
  nonce, as `conversationbundle.Verify` reads it. A statement signed more than
  `authorisation.Skew` (5 minutes) from when the Identity Agent takes it is
  rejected and joins nothing, because the verifier would fault it.
- **What the app returns is checked before it is passed on** (`Trail.Read`).
  Each committed entry's words and salt must hash to its fingerprint (a private
  agent's entry, to its `ciphertext_hash`), in the trail's order. Words for an
  entry that is pending or not kept are dropped and are not a mismatch. Words
  that do not hash, an entry the trail lacks, a repeat, one out of order, or a
  committed entry left out refuse the whole read with "the stored conversation
  does not match its record". Every read hands the governance record the
  person, the range and the outcome, and no words.

## Consequences

- A refused or not-kept message leaves a signed, wordless record, and leaves
  no words anywhere.
- An app that is down, slow, lying or broken into cannot make an entry
  committed that the Identity Agent did not check, and cannot widen who may
  write.
- A sender's retry is safe: one id, one result.

## Reversing it

Nothing in this repository depends on the store: the core keeps only the format
and the checks, and no export carries a person's statement entry. The fields it adds to the record are optional, so a
record without them verifies as before.
