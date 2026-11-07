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
it. In an ordered record, version 0 is old only if it comes **before the first
version 1 entry**; a version 0 entry after a version 1 entry is a fault, and a
verifier treats the record's version 0 entries as old only on that condition.

## The statement

`IA-PERSON-MSG-V1`, then these fields, one per line, in this order, joined by a
newline (0x0a), no trailing newline; an absent field is an empty line:
`agent` (the Identity Agent that holds the conversation), `conversation`,
`message_id`, `kind`, `from`, `signer`, `to`, `in_reply_to`,
`range_first`, `range_last`, `nonce`, `time`, `fingerprint_version`
(decimal), `fingerprint`. It is signed with the Ed25519 key `signer` names, as
an `IA-AGENT-MSG-V1` statement is.

## Refused

A statement is read as JSON with exactly the fields above: a field not listed,
a string field that is not a JSON string, or a `fingerprint_version` that is not
a JSON integer (`true`, `1.0`, `"1"`) is refused; a field left out is empty (0
for the version). It is then refused if: `agent`, `conversation`, `message_id`, `kind`, `from`,
`signer`, `nonce`, `time` or `fingerprint` is empty; any field holds a CR or
LF; `kind` is not one of `message`, `ask`, `split`, `hand-off`, `close`,
`reopen`; `to` is empty for a message, ask, split or hand-off, or not empty for
a close or reopen; a split has an empty `range_first` or `range_last`, or any
other kind has either; `fingerprint_version` is not 1 (0 and every other
value are refused); `nonce` is under 16 **bytes** (UTF-8; a nonce of 8 two-byte characters is
enough); `time` is not RFC 3339 as Go's `time.Parse` reads it: `YYYY-MM-DDTHH:MM:SS`,
an optional fraction after `.` or `,`, and then `Z` or `+hh:mm` / `-hh:mm`, all
ASCII, a capital `T`, no spaces; a date alone, `20261106T100000Z` and a space in
place of the `T` are refused, as are an hour of 24, a day that does not exist
and a leap second. (The hour may be one digit.)
