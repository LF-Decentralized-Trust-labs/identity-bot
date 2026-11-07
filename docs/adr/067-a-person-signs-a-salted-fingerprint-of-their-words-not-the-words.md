# ADR-067: A Person Signs a Salted Fingerprint of Their Words, Not the Words

**Status:** Proposed
**Date:** 2026-11-06
**Deciders:** Rob Andersen
**Amends:** ADR-047 (AI agents talk through the Identity Agent that holds them) — the part that says a person's message is the request their controller signed, which carries the words

---

## Context

An app can keep the words of a conversation while the Identity Agent keeps only
the record of who said what, in what order, signed. For that to hold, a
signature must prove a person said something **without containing it**.

Today a person's signed request carries the words themselves
(`agentmessage.ControllerProof.RequestBytes`: the exact bytes the person's app
signed, ADR-047's amendment of 2026-10-29). A record that keeps that signature
keeps the words. And the digest it commits to, `agentmessage.HashBody`, is
unsalted, so anyone who sees a record can confirm a short message ("yes",
"approved") by hashing guesses, and can spot the same message in two
conversations.

An AI agent's body already signs a statement over a digest of the words
(`IA-AGENT-MSG-V1`, ADR-047). A person needs the same, with a digest that
cannot be guessed.

## Decision

### A fingerprint is a hash over a salt and the words

```
fingerprint = Blake3-256( tag ‖ salt_length ‖ salt ‖ words )   written as a CESR "E" digest
tag         = the ASCII bytes "IA-FINGERPRINT-V1"
salt_length = the salt's length in bytes, as two bytes, big-endian
```

- The **signer makes the salt**: at least 16 bytes (128 bits) from a secure
  random source, **new for every message**, at most 1024 bytes. The person's
  device makes it for a person's message; an AI agent's body makes it for its
  own and sends it with the words.
- The salt travels and is kept **with the words**, never in a record, a log or
  a signed statement. Whoever holds the salt holds the words too, so keeping it
  there exposes nothing more.
- The length is in the preimage so no salt/words pair can be read as another
  split of the same bytes.
- **A private agent's entries** (entries the Identity Agent holds only as ciphertext) use
  the same construction over their **ciphertext**, and the record keeps that
  fingerprint as its `ciphertext_hash`. One construction serves both.

### The version is inside what is signed

The statement names the fingerprint's version, so it cannot be swapped.

- **Version 1** is the construction above.
- **Version 0** is today's unsalted `HashBody`. It has no salt. It is accepted
  **only when verifying a record made before this change**. A new write that
  carries version 0 is refused, so no sender can fall back to an unsalted
  fingerprint.

Any other version is refused.

**When version 0 is old.** A verifier treats a version 0 fingerprint as made
before this change only if it comes **before the first version 1 entry** of the
record it is in. Once a record has a salted entry, a later version 0 entry is a
fault, so a version 0 fingerprint cannot be written into a record that has
moved on (`agentmessage.CheckVersionOrder`; the verifier passes
`recorded=true` to `CheckFingerprint` only for an entry that rule accepts as
old). A conversation's trail, which starts at version 1, uses the same rule
offline (ADR-068).

### The person signs a statement

`IA-PERSON-MSG-V1`, signed with the key of the person's device or session
(a session key is the one a sign-in is bound to, ADR-066; `agentbody.Sign`, so
the same signature form as a body's). One field per line,
in this order, joined by a newline (0x0a), no trailing newline, as
`IA-AGENT-MSG-V1` is:

```
IA-PERSON-MSG-V1
agent               the Identity Agent that holds the conversation
conversation        the conversation it is in
message_id          the sender's own id for this message
kind                message | ask | split | hand-off | close | reopen
from                the person
signer              the identifier of the key signing (the device or session)
to                  the AI agent addressed, the new owner, or a split's owner
in_reply_to         the message it answers, or empty
range_first         a split's first entry id, else empty
range_last          a split's last entry id, else empty
nonce               fresh, at least 16 bytes
time                RFC 3339
fingerprint_version 1
fingerprint         the salted fingerprint of the words
```

- **It names the Identity Agent.** A conversation id is made by whoever opens
  the conversation and nothing makes it unique across Identity Agents, and a
  close or reopen has no recipient, so the id alone would scope it to nothing.
  Naming the Identity Agent keeps a statement signed for one Identity Agent's
  conversation from being replayed into another's of the same id.
- **It names the recipient and the kind**, so one signed statement cannot be
  replayed as another kind or re-threaded to somebody else.
- **`message_id` is the sender's own, bound into the signature.** The Identity
  Agent scopes it to the conversation and author; the same id with the same
  statement returns the earlier result, and a different statement under that id
  is refused. (That is the Identity Agent's rule to enforce; this ADR defines
  only what is signed.)
- **A split names the range it carries** (`range_first`, `range_last`) and its
  owner in `to`. Every other kind has both range lines empty.
- **`close` and `reopen` name no recipient** (`to` empty). Every kind still
  carries a fingerprint; for an entry with no words it is the fingerprint of
  the empty string under a fresh salt.
- A field may not contain a line break, which would let one statement be read
  as another.

### What this ADR does not do

It defines the statement, the fingerprint and their vectors, and the checks a
verifier can make from them. It does not say who may write, what the Identity
Agent keeps, or when an entry is committed; those rules, and the gateway's
refusal of version 0 for new writes, land with the work that uses this format
(ADR-068 for the trail and the order of a write; the gateway route is a later change). Until the gateway accepts this statement, a person's
message is still the controller's signed request.

## Consequences

- A record can keep every person's signature without keeping a word, and a
  fingerprint in it cannot be confirmed by guessing.
- An exported conversation carries each entry's salt with its words, so a
  verifier recomputes every fingerprint offline.
- A person's app and an AI agent's body now both sign over a fingerprint, and
  one function (`agentmessage.Fingerprint`) makes it for both.
- Version 0 stays readable forever for old records, and is never writable.
- `IA-PERSON-MSG-V1` is a new signed string: a reader that does not know it
  refuses it, and nothing about `IA-AGENT-MSG-V1/V2` or the controller's
  request changes.

## Reversing it

Nothing yet depends on this: no gateway accepts the statement. The version
number lets a later construction replace the hash without breaking records.
