# The signed fingerprint (ADR-067)

A person signs a statement over a salted fingerprint of their words, never the
words. `check_signed_fingerprint_vectors.py` is written from this page.
Worked examples: `../../agentmessage/signed-fingerprint-vectors.json`.

## The fingerprint

Version 1: `Blake3-256(tag ‖ salt_length ‖ salt ‖ words)` as a CESR `E` digest
(the same encoding as `body_hash`), where `tag` is the ASCII bytes
`IA-FINGERPRINT-V1` and `salt_length` is two bytes, big-endian. The salt is 16
to 1024 bytes, made fresh by the signer for every message, and kept with the
words, never in a record. Anything else about the salt is refused.

Version 0 is the unsalted Blake3-256 digest of the words. It has no salt and
verifies only in a record made before version 1. A new statement never carries
it.

## The statement

`IA-PERSON-MSG-V1`, then these fields, one per line, in this order, joined by a
newline (0x0a), no trailing newline; an absent field is an empty line:
`conversation`, `message_id`, `kind`, `from`, `signer`, `to`, `in_reply_to`,
`range_first`, `range_last`, `nonce`, `time`, `fingerprint_version`
(decimal), `fingerprint`. It is signed with the Ed25519 key `signer` names, as
an `IA-AGENT-MSG-V1` statement is.

## Refused

A statement is refused if: `conversation`, `message_id`, `kind`, `from`,
`signer`, `nonce`, `time` or `fingerprint` is empty; any field holds a CR or
LF; `kind` is not one of `message`, `ask`, `split`, `hand-off`, `close`,
`reopen`; `to` is empty for a message, ask, split or hand-off, or not empty for
a close or reopen; a split has an empty `range_first` or `range_last`, or any
other kind has either; `fingerprint_version` is not 1 (0 and every other
value are refused); `nonce` is under 16 characters; `time` is not RFC 3339.
