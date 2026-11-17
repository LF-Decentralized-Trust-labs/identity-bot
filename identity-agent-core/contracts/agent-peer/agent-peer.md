# A message between AI agents that two Identity Agents hold

How an AI agent one Identity Agent holds sends a message to an AI agent another
Identity Agent holds, carried between the two Identity Agents as accepted
contacts (ADR-085). It is the same whoever holds each Identity Agent, a person
or an organisation. An implementation that already speaks the contact envelope
and the conversation record (ADR-068) needs only what is here to interoperate.

The policy around it — which of the AI agents an Identity Agent holds may
message or be messaged by a contact, at what rate, with how many asks
unanswered — is each side's own, kept and applied by whatever keeps its AI agents,
and never on the wire. A receiver tells a sender nothing about why it refused a message.

## The two payloads

Both travel inside the envelope two Identity Agents already use as accepted
contacts (an introduction, then an acceptance): an authcrypt JWM between the two
sides' identifiers, signed with the hybrid messaging signature, fresh and
replay-refused. The envelope establishes which Identity Agent sent the message;
nothing here repeats it as a claim the receiver trusts.

### `agent-peer-message`

The body is a JSON object with these four fields (a receiver reads those it knows and ignores any other):

- `exn` — the signed KERI exchange message (below), as KERI text.
- `pq_sig` — the ML-DSA-65 signature over it (below), unpadded base64url.
- `words` — the message itself, UTF-8, at most 65536 bytes, non-empty.
- `salt` — the salt of the words' fingerprint, 16 to 1024 bytes, unpadded
  base64url in its one canonical string. It travels and is kept **with the
  words and nowhere else**.

### `agent-peer-directory`

The body is the list of AI agents an Identity Agent tells a contact it may reach,
so the contact can write each one `name@alias`:

```json
{ "agents": [ { "aid": "<identifier>", "name": "<shown name>", "role": "<optional>" } ] }
```

It carries no signature of its own and grants nothing: what a contact may reach
is the owner's rule, held and checked by the Identity Agent that holds the AI
agent, whatever a directory says. A receiver keeps it only when it can be shown
as it stands (the rules below).

## The exchange message

What the sending Identity Agent signs is a KERI exchange message
(`exn`): KERI's own message for one identity saying something to another. It is
the message keripy builds with `exchanging.exchange` and a keripy `Exchanger`
accepts, byte for byte. The implementation is keri-go's `exchange.go` (ADR-037:
one KERI engine), and its vectors are built by keripy.

The message is these fields, in this order, in JSON with no white space and
nothing after it. `v` declares the message's size in bytes; `d` is its
self-addressing identifier: the Blake3-256 digest, as CESR qb64 (code `E`), of
the message with `d` written as 44 `#` characters.

| Field | Value here |
|---|---|
| `v` | `KERI10JSON` then the size as six lower-case hex digits, then `_`. |
| `t` | `exn`. |
| `d` | The identifier, as above. |
| `i` | The sender: the sending Identity Agent's **Ed25519 messaging key as a non-transferable identifier** (CESR code `B`). |
| `rp` | The recipient: the receiving Identity Agent's identifier. |
| `p` | Empty. A message follows no earlier exchange message here; `in_reply_to` names the ask. |
| `dt` | When it was sent, as keripy writes a date: `YYYY-MM-DDTHH:MM:SS.ffffff+00:00`, in UTC, and in no other spelling. |
| `r` | The route: `/ia/agent/peer/` then the kind: `ask`, `reply`, `failure` or `progress`. |
| `q` | `{}`. |
| `a` | The content (below). |
| `e` | `{}`. |

`a` holds these, in this order (`in_reply_to` absent for an `ask`), and nothing
else:

| Field | What it is |
|---|---|
| `i` | The recipient again (`rp`), as keripy writes a message that has one. |
| `from_aid` | The sending Identity Agent's identifier, as its contacts know it. |
| `from_agent` | The AI agent the sending Identity Agent holds. |
| `to_agent` | The AI agent the receiving Identity Agent holds. |
| `message_id` | This message's own name. |
| `in_reply_to` | The `message_id` of the ask a `reply`, `failure` or `progress` answers. |
| `fingerprint_version` | `1`: the salted fingerprint. No other version is written or read; a new format does not start with the unsalted digest. |
| `fingerprint` | The fingerprint of the words (below). |

**Identifiers.** `rp`, `from_aid`, `from_agent`, `to_agent`, `message_id` and `in_reply_to`
are one to 128 of the letters, digits and `_ . : -`, and nothing else: no space,
control character, text-direction mark, or `/`. (A party is written
`<Identity Agent>/<AI agent>` in a conversation, and a trailing `/e<digits>` of a
message id reads as a place.) A `message_id` or `in_reply_to` shaped like an
entry's place in a conversation (`e` and a positive number) is refused: a trail
that files an entry by its place would read two messages as one.

**The fingerprint** is ADR-067's version 1: the Blake3-256 digest, as CESR
qb64 (code `E`), of the bytes `IA-FINGERPRINT-V1`, the salt's length as two
bytes (big-endian), the salt and the words. Each message has a salt of its own,
made by the sender, so the same words twice have two fingerprints and nobody
who sees an exchange message can confirm a short answer ("yes", "approved") by
hashing guesses. The salt is never inside the signed message.

## The two signatures

1. **Ed25519, as KERI attaches one.** The signed message is the exchange message
   followed by one attachment, a non-transferable receipt couple: `-CAB`, then
   the sender `i` (44 characters), then the signature (`0B` and 86 characters,
   CESR) of the sender's key over the exchange message's bytes. keripy takes
   this with nothing else, because a non-transferable identifier **is** its
   key. This is the `exn` field of the payload.
2. **ML-DSA-65.** The same messaging keys sign everything an Identity Agent
   signs with an Ed25519 key and an ML-DSA key together, and a reader requires
   both (no classical-only fallback). The ML-DSA-65 signature (FIPS 204, no
   context) is over the bytes `IA-AGENT-PEER-PQ-V1`, a line feed, and then the
   exchange message. It is the `pq_sig` field. The tag keeps it from being read
   as a signature made for anything else with the same key.

**Why the sender is a messaging key and not the key-log key.**
The key-log key of the identity an Identity Agent holds is held by the device
that controls it and cannot sign every message the Identity Agent sends. The
Identity Agent signs with its messaging keys, which its key log commits to (the
DID's `kel_sig`, ADR-024, ADR-075). So `i` names a key, and a receiver accepts
it only when that key is the one in the sender's DID that it holds for that
contact. The sending Identity Agent's identifier is named in `a.from_aid`, and
its key log vouches for the keys. A receiver does not check the key log again for each message, as it does not for any message from a contact; the DID was tied to the log when the contact was made. A reader that later checks a kept message must hold the keys the log vouched for when the message was made; the conversation bundle requires them (see below). A rotation of the messaging keys is a new `i`, and a contact whose keys changed is not heard from until they are refreshed.

### What the signatures prove, and what they do not

They prove that the sending Identity Agent vouched that an AI agent it holds
sent these words to the named AI agent of the receiving Identity Agent, at that
time. They do **not**
prove which machine or brain produced the words, and the receiver cannot check
the AI agent's own keys. The sending Identity Agent answers for the AI agents it
holds. This is weaker than the countersignature between AI agents one Identity
Agent holds (ADR-047) and is chosen as the smaller thing a stranger can honestly check.

## How a receiver checks a message

A receiver refuses a message that breaks any of these rules (`agentpeer.Verify`).
Each refusal has a stable `code`. A message that breaks one rule gets that
rule's code; which code a message breaking several rules gets is not part of
the contract, and nor is the refusal's English text.

| Code | Refused when |
|---|---|
| `no_message` | There is no `exn`. |
| `unreadable` | The `exn` is not a KERI exchange message in its one form with a valid identifier, carrying exactly one non-transferable couple whose key is the sender `i` and whose signature holds over the message; or `a` has a field this contract does not define. |
| `not_signed` | `i` is not the Ed25519 messaging key of the sending Identity Agent as the receiver holds it, or the ML-DSA-65 signature is missing or does not hold. |
| `kind` | The route is not `/ia/agent/peer/` and one of the four kinds. |
| `fingerprint_version` | `fingerprint_version` is not `1`. |
| `not_one_form` | `p` is not empty, `a.i` is not `rp`, or the message is not the one this contract writes for its statement (an extra or reordered field, a modifier in `q`, anything in `e`). |
| `wrong_sender` | `a.from_aid` is not the identifier of the Identity Agent whose keys signed, or is not the one the envelope said sent it. |
| `field` | An identifier does not meet the rule above. |
| `reply_to` | An `ask` answers something, or a `reply`, `failure` or `progress` answers nothing. |
| `place_id` | A `message_id` or `in_reply_to` has the shape of an entry's place. |
| `fingerprint` | The fingerprint is not a digest, or is not that of the words under the salt. |
| `time` | `dt` is not in its one spelling, or is more than an hour from the receiver's clock either way. |
| `wrong_recipient` | `rp` is not the receiver. |
| `words` | The words are empty or over 65536 bytes. |
| `salt` | The salt is missing, under 16 or over 1024 bytes, or not in its one spelling. |

Whether the receiver then keeps the message — that the sender is an accepted
contact, that the owner lets that contact reach the named AI agent, at that rate
— is the receiver's own, applied after this and told to the sender as nothing
but a refusal.

### A message is not passed on

An ask that came from another Identity Agent is not forwarded to a third. This
is **the sender's own policy** and nothing on the wire proves it: an AI agent
that took an ask can quote it in a new message to anybody its own owner's rule
lets it reach. What can be shown is shown: a conversation record is a fault
when an ask to another Identity Agent's AI agent is recorded inside a
conversation another Identity Agent's AI agent opened (`conversationbundle`),
and each owner's rule is applied by the sender before sending and by the
receiver on receipt.

## How an AI agent's grant is checked

An AI agent may message an AI agent another Identity Agent holds only under the
capability `agent.message.peer`, which is not `agent.message.send` widened
(`agentpeer.CheckPeerGrant`). It is the sending AI agent's own grant, checked
by the sending Identity Agent before it sends, when the grant is issued, and by
a conversation bundle's checker; the receiver never sees it:

- the entry is an object whose only keys are `contact` and `agent`;
- `contact` is a non-empty list of text naming the contacts (other Identity
  Agents, by identifier) it may reach;
- `agent`, when it is given at all, is a **non-empty** list of text naming the AI
  agents; a narrowing constraint that is badly shaped (text, an empty list, a
  list of anything but text) allows nothing, never "every AI agent";
- the contact asked for is listed, and the AI agent is listed when `agent`
  is given.

A grant with no `agent.message.peer` entry allows nothing.

## How a receiver checks a directory

A directory is kept only when it can be shown as it stands (`Directory.Check`),
refused with the exact text otherwise:

- at most 200 AI agents;
- each `aid` an identifier (as a message's fields, above);
- each `name` one to sixty-four characters, trimmed to itself, with no `@` and
  nothing that cannot be read as itself (no control, format, private-use or
  unassigned character); a cross-script look-alike is not caught, because the
  name is shown beside the alias the owner chose;
- each `role` one short line of at most 200 characters, shown the same way;
- no two entries of one name, and no AI agent named twice.

## In the conversation record

An entry sent by an AI agent another Identity Agent holds is countersigned by
this Identity Agent, as a person's is, and carries `peer_proof`: the other
Identity Agent's signed `exn` and `pq_sig`, without the words and without the
salt. Its sender is written `peer:<that Identity Agent>/<its AI agent>`. The record
must say what the exchange message says — `from`, `to`, `kind`, `message_id`,
`in_reply_to`, and `body_hash` equal to its `fingerprint` — and is checked with
the other Identity Agent's messaging keys (`agentmessage.Record.CheckPeerProof`).
The countersignature is addressed (`to`) to that Identity Agent alone, as
`did:keri:<that Identity Agent>`: the AI agent is named in the record, which is
the body. What this Identity Agent's own countersignature proves is only that it
recorded the entry, in that place and at that time, and nothing about the
sender. The schema is `peer_proof` in
`../agent-message/agent-message.schema.json`. A conversation bundle checks such
an entry the same way and must carry that Identity Agent's messaging keys tied to
its key log, like any countersigner's; where it carries the words it carries the
salt with them (`conversationbundle.Entry.Salt`) and the fingerprint is checked.
It can show that the other Identity Agent said the AI agent it holds sent the
words, and says so in what it cannot rule out. A conversation that another
Identity Agent's AI agent opened begins with its ask as the first entry, at
depth 1, and is closed only by this Identity Agent's owner (ADR-077): the other
side's statement has no close.

## Worked examples

`../agentpeer/peer-vectors.json`: two Identity Agents' messaging keys from
published seeds (Ed25519 RFC 8032, ML-DSA-65 FIPS 204); five messages taken,
each with the statement, the words, the salt, the exchange message's exact
bytes, its identifier, the whole signed message and the ML-DSA signature; 25
messages refused, each breaking one rule and carrying its `code` and the keys it
is checked against; directories kept and refused; and grants that allow and
refuse. `check_peer_vectors.py` rebuilds every message from the statement,
checks the identifier and the Ed25519 signature with no library but `blake3`,
and re-applies every rule from this prose. Where `dilithium_py` is installed it
checks the ML-DSA signatures too, and where `keri` (keripy 1.3.6) is installed
it gives every signed message to a keripy `Exchanger`, which must take it. The
Go tests run it where Python and `blake3` are installed.
