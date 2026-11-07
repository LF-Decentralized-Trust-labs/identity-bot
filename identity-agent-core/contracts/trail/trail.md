# The trail (ADR-068)

What the Identity Agent keeps of a conversation an app holds the words of. No
entry holds words, a salt or a preview. Implementation: `../../trail`.

## An entry

JSON object, no other field allowed: `seq` (from 1, no gaps), `id` (`e` and
`seq`), `prev` (the previous entry's chain hash, empty for the first),
`recorded` (RFC 3339), `refusal` (a reason; present only on a refusal),
`ciphertext_hash` (only for a private agent's entry; equals the statement's
fingerprint), `statement` (an `IA-PERSON-MSG-V1` statement, see
`../agent-message/signed-fingerprint.md`), `verkey`, `signature`, and `outcome`
(`state` `committed` or `not-kept`, `reason` required for `not-kept`, `time`).
An entry with neither `refusal` nor `outcome` is pending.

## The chain hash

`Blake3-256` as a CESR `E` digest (the encoding of `body_hash`) of these lines
joined by a newline, no trailing newline:

`IA-TRAIL-ENTRY-V1`, `seq` (decimal), `id`, `prev`, `recorded`, `refusal`,
`ciphertext_hash`, `verkey`, `signature`, and the same digest of the
statement's `IA-PERSON-MSG-V1` bytes. An absent field is an empty line. The
outcome is not in it. The latest entry's chain hash is the trail's head.

## What a reader checks

For each entry: `seq` and `id` follow the one before; `prev` equals the one
before's chain hash; the statement names the same conversation as the first;
the signature is the statement's signer's over its bytes; `recorded` is RFC
3339; a refusal has no outcome; an outcome is `committed` or `not-kept`, and a
`not-kept` gives its reason; no field holds a line break. A committed, a
not-kept and a refused entry are checked the same way and none needs words.
Given an app's words and salts, each committed entry's fingerprint is
recomputed; words for an entry that is not committed are a fault.
