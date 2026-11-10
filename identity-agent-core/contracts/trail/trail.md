# The trail (ADR-068)

What the Identity Agent keeps of a conversation an app holds the words of. No
entry holds words, a salt or a preview. **There is one chain per conversation:**
the countersigned entries of `../agent-message/agent-message.schema.json`
(`record`), each carrying the hash of the one before it
(`entry_hash`), and one verifier of it, `../../conversationbundle` (see
`../conversation-bundle`). The trail is that chain extended, not a second one.
The check that a person's statement is the person's and was signed in time is
`../../trail` (`CheckAuthor`, `CheckFresh`). What keeps a trail, and the delivery
queue beside it, is an add-on's and is not in this repository (ADR-068,
ADR-069).

## What a person's entries add to the record

A person's statement over a fingerprint (`../agent-message/signed-fingerprint.md`)
is a `record` with `person_proof` (the statement, `verkey`, `signature`) as its
sender's proof, in place of `controller_proof`. Its `kind` is the statement's,
`from` is `person:` and the statement's `from`, `to` and `in_reply_to` are the
statement's, and `body_hash` is the statement's `fingerprint`. Its id
(`message_id`) is `e` and its `seq`: the id the app keeps the words under.

Three more things are entries of the same chain:

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
