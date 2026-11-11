# The trail (ADR-068)

What is kept of a conversation an app holds the words of: the app keeps the
entries and the words, and the Identity Agent keeps the head and the count (see
"Where the trail is kept"). No entry holds words, a salt or a preview. **There is one chain per conversation:**
the countersigned entries of `../agent-message/agent-message.schema.json`
(`record`), each carrying the hash of the one before it
(`entry_hash`), and one verifier of it, `../../conversationbundle` (see
`../conversation-bundle`). The trail is that chain extended, not a second one.
The check that a person's statement is the person's and was signed in time is
`../../trail` (`CheckAuthor`, `CheckFresh`). What keeps a trail, and the delivery
queue beside it, is an add-on's and is not in this repository (ADR-068,
ADR-069).

## Where the trail is kept

**The store of record is the app that keeps the conversation.** It keeps the
countersigned entries and the words. What has to be proven is only a
fingerprint in the Identity Agent; everything else is the app's.

The chain is the one above, and nothing new: entry n has `seq` n and
`prev_hash` the hash of entry n-1 (`""` for n = 1); an entry's hash is
`agentmessage.Hash`, the Blake3-QB64 of the countersigned `plain`, a newline,
`ed_sig`, a newline and `mldsa_sig`.

- **The head** is the hash of the newest committed entry, `""` when there is
  none.
- **The count** is the number of committed entries. It equals the newest `seq`:
  there are no gaps.

### What the Identity Agent keeps

Per conversation: the head, the count, the opener's person reference, the
parties, and the open asks (message id, the party asked, answered or not). The
head and the count change in one transaction with the commit of an entry, and
never before it.

Any other copy of an entry in the Identity Agent is **transitory**: held until
the app has confirmed it keeps the entry and the recipient has collected it,
then deleted.

**Exception.** A conversation no app keeps (an AI agent speaking to another AI
agent, with no app named on it) keeps its whole trail in the Identity Agent,
because nothing else holds it.

### What a countersignature covers

The whole record (`plain`): id, conversation, `seq`, `prev_hash`, `ia_time`,
kind, `from`, `to`, `in_reply_to`, depth, `body_hash`, the sender's proof (the
statement, or `person_proof` with its signature), `grant_said`, `body_grade`,
`body_credential`, the person reference, `opened_by`, `refusal` and `outcome`.
`entry_hash` also covers the two signatures. The words are not covered, only
their fingerprint (`body_hash`). The signer is the Identity Agent for a person's
entry and for its own, and the AI agent for the AI agent's
(`agentmessage.Countersigner`). `prev_hash` is inside what is signed, so order
and membership are signed: nobody without a key can insert, remove or reorder an
entry without breaking a signature or the chain.

### How a copy is checked against the head and the count

Given the copy E1..Ek an app hands over, and the `(count, head)` the Identity
Agent reports (`conversationbundle.CheckCopy`; the signatures and each entry's
checks are `conversationbundle.Verify`'s, over the same entries):

1. Entries with `seq` above the count are **uncommitted**: left out by the copy
   check (`CheckCopy`), and never to be shown as part of the conversation. The app does not drop one by itself at a
   read, since the Identity Agent may be about to commit it; it goes when the
   Identity Agent tells the app to discard it (by its hash), or when a later
   entry takes its place.
2. The copy may hold **more than one entry at a place** (two writes raced for it
   and the loser is not yet discarded), in **any order**. Every place from 1 to
   `count` must hold at least one entry, each in this conversation, and each
   place's entry must say it is that place's. Two entries with one hash are one.
3. The committed entry at each place is **chosen from the head back, by hash,
   never by `seq`**: the entry whose hash is the head, then at each place the
   entry whose hash the entry after it names as its `prev_hash`. The first
   entry's `prev_hash` is `""`. The entries held at a place that are not the
   committed one are **ignored**: they never fail the check, and the result lists
   them so nobody reads a copy as holding one entry per place.
4. A chain of entries, each following from one held at the place before it, must
   end at the head. With a count of 0 nothing is committed, and the head must be
   `""`.

| Outcome | How it shows |
|---|---|
| removed from the end | a place at the end with no entry, none missing inside |
| removed or reordered inside | a place with no entry before a later one, or an entry that does not follow from one held before it. An entry inside the chain replaced by another with the same `seq` shows as this, not as *substituted*: the entry after it no longer follows from it |
| substituted | every place held and chained, but no chain ends at the head (a replaced last entry) |
| matches | all of the above hold |
| ignored | not an outcome: the entries held at a place that are not the committed one, reported beside any outcome that reaches the choice |

The outcome names are exactly as the table spells them, in lower case with
spaces (`CopyOutcome` in `conversationbundle`): "removed from the end", "removed
or reordered inside", "substituted", "matches" and "not countersigned". An app
that reports an outcome in its own words, or a reader of what an app reports
(an AI agent's tool, a UI), maps from these and does not assume another
spelling: an app that spells them with hyphens, as `removed-from-the-end`, is
translating, and that is its own. An export is read by place, not by the order
its entries are listed: the entries the verifier reads as the conversation are
the ones this check chose as committed, one for each place in order.

Steps 2 and 3 need no Identity Agent; step 4 needs the head, and shows the end as
of the head's time. There is one implementation of this check,
`conversationbundle.CheckCopy`; an add-on that keeps conversations calls it, with
a check of each committed entry's countersignature if it can make one, rather
than carrying its own.

### Where the head comes from

- **Live:** `GET /api/conversations/{id}/head`, answering
  `{"conversation", "count", "head"}` (`head` is `""` when `count` is 0). The
  owner and the owner's controllers may ask it, and so may the app that keeps the conversation, signing as
  the app (`../app-request/app-request.md`) with an App Grant that holds
  `conversation.head.read`. Any other caller, an app that does not keep the
  conversation, and a conversation that does not exist are all refused with the
  same 404 and the same words.
- **Offline:** an export carries `head`: a head statement, an envelope the
  Identity Agent signs with its messaging key (the one that countersigns a
  person's entries), of type `trail-head`, whose body is
  `{"conversation", "count", "head", "ia_time"}` and whose id is
  `trail-head:<conversation>:<count>`. The checker verifies the signature, that
  it names this conversation, that it is not dated after the export, and holds the
  entries to it as above. It shows the end as it stood at `ia_time`; an entry
  committed later is not shown missing, and an older genuine statement paired
  with entries cut back to its count passes, so a statement shows the end only as
  of its time. A bundle with no head statement says, when a person spoke in it through an
  app that may keep it, that it cannot rule out an entry cut off the end after
  the last anchor in the key history. Entries past the statement's count are
  left out of the report's messages and only counted. Recording the head in the key history would let a bundle show it
  without a statement; that is not part of the format yet (ADR-068).

### The order of a write

**Every entry is kept by the app before it is committed.**

- The Identity Agent countersigns an entry at `seq` count+1, with `prev_hash` the
  head, and hands it to the app with the words it holds only in passing.
- The app keeps the entry and the words and confirms the fingerprint it stored.
- Only then does the Identity Agent move the head and the count, in one step,
  and only if the head is still the one the entry was countersigned for;
  otherwise it tells the app to discard that entry, named by its hash. Two
  writes racing for one place are both kept by the app until the loser is
  discarded, so a copy may hold more than one entry at a place for a while.
- The Identity Agent's own copy of an entry is transitory, held until the app
  confirms and then deleted. An entry the app never confirmed is never committed.
- A person's message the Identity Agent did not accept leaves nothing in the
  trail except a refusal.

## What a person's entries add to the record

A person's statement over a fingerprint (`../agent-message/signed-fingerprint.md`)
is a `record` with `person_proof` (the statement, `verkey`, `signature`) as its
sender's proof, in place of `controller_proof`. Its `kind` is the statement's,
`from` is `person:` and the statement's `from`, `to` and `in_reply_to` are the
statement's, and `body_hash` is the statement's `fingerprint`. Its id
(`message_id`) is `e` and its `seq`: the id the app keeps the words under.

On an app's request to `/api/mcp/agents/{asset id}/conversations...`, the
statement's `to` is the AI agent's identifier (the one its entries are addressed
to, the asset's `pairwise_aid`), never the asset id in the route. The Identity
Agent resolves the route's asset id to that identifier and refuses a statement
to any other.

Three more things are entries of the same chain (for a conversation an app
keeps, a person's entry is kept by the app before it is committed, so it is
never *pending* and no *not kept* outcome is written for it: ADR-068; the
checker still reads those forms):

| Entry | How it is written |
|---|---|
| **pending** | the person's entry as above, written before anything is forwarded to the app |
| **refusal** | the person's entry with `refusal` set (a plain reason). It records who tried, when and why, and nothing was forwarded |
| **outcome** | a record of kind `outcome` from the Identity Agent, with `in_reply_to` the entry's id and `outcome` (`entry`, `state` `committed` or `not-kept`, `reason` required for `not-kept`). It carries no sender's proof; the countersignature is the proof |

An entry is never changed: it is pending until an outcome entry follows it,
and a refusal never has one. **Committed**, **not kept**, **pending** and
**refused** are therefore read from the chain, and an outcome follows its entry
without breaking the chain. A private agent's entry has `ciphertext_hash`
(equal to its fingerprint).

An AI agent's entries are the existing records, countersigned by the AI agent
(ADR-047), in the same chain. They are committed by being countersigned.

## What a reader checks

`conversationbundle.Verify` checks every entry the same way it did, and for
these: the person's statement is signed by the key it names and names this
Identity Agent; the record says what was signed; its time is within the stated
skew of the Identity Agent's stamp; an entry that answers another answers one
that was kept at that point; an entry the Identity Agent allowed does not reuse
an id or a nonce its author used before (a refusal may, and uses them up); an
outcome is the Identity Agent's, is about an earlier entry that was pending, and
ends it once; the entry's id is `e` and its `seq`; and a person's version 0
words (a paired app's signed request) do not follow a version 1 entry (ADR-067).
A refusal, a not-kept entry and a kept entry are checked alike and none needs
words. An export that carries a kept entry's words (`body`) and salt (`salt`) has
the fingerprint recomputed; words offered for a refused or not-kept entry are a
fault; words left out are listed as something the check could not rule out.
Who may write is the Identity Agent's rule from its roster and is not replayed.
