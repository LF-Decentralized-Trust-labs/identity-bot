# ADR-068: A Conversation's Trail Keeps Who Said What, Never the Words

**Status:** Proposed
**Date:** 2026-11-06
**Deciders:** Rob Andersen
**Builds on:** ADR-067 (a person signs a salted fingerprint of their words, not the words)

---

## Why a new ADR

ADR-067 defines what is *signed*: the fingerprint and the person's statement.
This ADR defines what the Identity Agent *keeps* and the order in which it
keeps it: a record of its own, with its own states, chain and rules. It does
not amend ADR-067; ADR-067 says these rules "land with the work that uses this
format", and this is that work.

## Context

An app can keep the words of a conversation while the Identity Agent keeps the
record of who said what, in what order, signed. Two things must then hold: the
Identity Agent decides what may be written from its own record alone, and an
app that is broken into, or down, cannot make anybody see, or be told, a
conversation that did not happen.

## Decision

### The trail

For each conversation the Identity Agent keeps a **trail**: its opener, its
owner, whether it is open or closed, every hand-off with who made it, and an
ordered list of entries. **An entry holds no words, no salt and no preview.** It
holds:

- a sequence number counting from 1 and an id derived from it (`e1`, `e2`…),
  under which the app keeps the words;
- the author's statement (ADR-067), the key that signed it and the signature,
  so the fingerprint, the kind, the recipient, the sender's message id and the
  nonce are all inside what the author signed;
- the chain hash of the entry before it, and the time it was recorded;
- for an entry the Identity Agent holds only as ciphertext, the
  `ciphertext_hash`, which is the statement's fingerprint;
- either a **refusal reason** or, once known, an **outcome**.

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

1. **Prove an author.** The statement must be well formed, its signature must
   be its signer's, and the Identity Agent's own records must say that key
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

Each entry carries the hash of the one before it:

```
chain_hash = Blake3-256( "IA-TRAIL-ENTRY-V1" \n seq \n id \n prev \n recorded \n
                         refusal \n ciphertext_hash \n verkey \n signature \n
                         Blake3-256( statement bytes ) )
```

(one field per line, no trailing newline). It covers everything but the
outcome, so an outcome follows without breaking the chain, and nothing can be
slipped in, reordered, removed or have a refusal's reason rewritten unnoticed.
The Identity Agent records the latest entry's chain hash, the **head**, in its
key history (a later change), which is what catches a cut-off end.

### Offline verification

A reader with only an exported trail checks: the sequence and ids, the chain,
every author signature, that each statement names this conversation, and that
an outcome is allowed. **A committed entry, a not-kept entry and a refusal all
verify alike**, since each keeps its fingerprint and signature and none keeps
words. With the words and salts an app exports, a reader also recomputes every
committed entry's fingerprint; words offered for an entry that was not kept
are a fault. A trail with a field it does not know is refused, since it has
nowhere to carry words.

## What this ADR does not do

- It does not cover an **AI agent's** entries (the host statement and the
  Identity Agent's countersignature over a salted `body_hash`, the turn limit
  and an agent's onward ask). Those need the agent's statement to name its
  fingerprint version, which `IA-AGENT-MSG-V1/V2` does not yet; a later change.
- It does not store the trail durably, record the head in the key history,
  rate-limit, or serve reads. The package keeps the trail in memory behind the
  rules above; the Identity Agent's table and routes use it.
- It does not decide `@agent` reach beyond "an AI agent the writer may use".

## Consequences

- A refused or not-kept message leaves a signed, wordless record, and leaves
  no words anywhere.
- An app that is down, slow, lying or broken into cannot make an entry
  committed that the Identity Agent did not check, and cannot widen who may
  write.
- A sender's retry is safe: one id, one result.

## Reversing it

Nothing yet depends on this: no route uses the trail. The tag in the chain
hash is versioned.
