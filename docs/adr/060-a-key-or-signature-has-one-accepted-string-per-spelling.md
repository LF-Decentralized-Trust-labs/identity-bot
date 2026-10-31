# ADR-060 — A key or signature has one accepted string per spelling

**Status:** Accepted
**Date:** 2026-10-31
**Relates to:** ADR-031 (Who witnesses what), ADR-049 (One signing form for every service provider request)

## Context

A key, signature or count is bytes, but it travels as text, and the usual
encodings let one value be written as several different strings. A lenient
decoder reads all of them as the same bytes. The code that decides "is this
the same witness?", "is this key already on the list?" or "has this receipt
been counted?" compares text, so it sees different values where there is one.
A witness that sent the same receipt under two spellings of its key was
counted twice toward the threshold.

There are five ways one value gets several strings. The examples below all
encode the same 32-byte Ed25519 public key.

**qb64 lead bits.** qb64 makes the raw bytes fill whole base64 characters by
adding zero bytes in front, then writes the derivation code over the first
characters. For a 32-byte key with code `D`, one zero byte is added. Two of
its bits land in the second character and must be zero. A decoder that drops
them reads four strings as one key:

```
DFDYWOCYXsx_YEGKrwzFq1h_QsJXCohAlanozKzQ9lRc   lead bits 00, the only one accepted
DVDYWOCYXsx_YEGKrwzFq1h_QsJXCohAlanozKzQ9lRc   lead bits 01
DlDYWOCYXsx_YEGKrwzFq1h_QsJXCohAlanozKzQ9lRc   lead bits 10
D1DYWOCYXsx_YEGKrwzFq1h_QsJXCohAlanozKzQ9lRc   lead bits 11
```

A 64-byte signature (`0B`, 88 characters) carries four such bits, so it has 16
strings.

**Base64 spare bits.** 32 bytes take 42⅔ base64 characters. The last
character has two bits that carry nothing, so `…VFw`, `…VFx`, `…VFy` and
`…VFz` decode the same:

```
UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw    spare bits 00, the only one accepted
UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFx    spare bits 01
```

**Line breaks.** Go's and Python's default base64 decoders skip `\r` and
`\n` anywhere in the string.

**Hex case.** `50d858e0…` and `50D858E0…` are the same bytes.

**Counts.** A KERI event writes counts (`s`, `bt`, and `kt`/`nt` when they are
a number) in hex, and `"2"`, `"02"` and `"002"` read as the same number.

## Decision

**Every key, signature, hex value and count that is decoded is read in
exactly one string for each spelling it may arrive in.** A string that only a
lenient decoder would read is refused.

- **qb64** (keys, identifiers, signatures, indexed signatures): the exact
  length for its code, base64url only, and every lead bit zero. This is the
  form keripy and keri-go both write. `iacrypto.DecodeQB64` reads it, and
  keri-go reads every CESR value the same way. An indexed ML-DSA-65
  signature, whose provisional encoding puts raw base64url after its code and
  index with no lead bytes, is read at exactly its length and in base64url
  only (`iacrypto.DecodeIndexedMLDSASig`).
- **Raw keys and signatures where a format names unpadded base64url**
  (signatures and keys on DIDComm messages, activity log records, the stored
  hardware-signer attestation and its public key, the sealing keys an AI
  agent's body declares, update manifests and their signing keys, the key an
  app is given to check calls from the Identity Agent, URL relay admissions): only that alphabet, no padding, no line breaks, and zero spare
  bits. `iacrypto.DecodeBase64URL` and `DecodeBase64URLSized` read it. URL
  relay admission applies the same rule in its own `signatureOf`, because
  `relayproto` is a module a URL relay imports on its own, without the core.
- **Raw keys and signatures in a field that accepts more than one base64
  spelling** (because different languages write different ones): each of the
  four spellings (base64url or standard alphabet, padded or not) is read
  strictly, at the exact size, with zero spare bits and no line breaks.
  `iacrypto.DecodeSized` reads it. A key may still arrive in more than one of
  those spellings, so code that compares keys from such a field compares the
  decoded bytes, never the text.
- **Hex:** lowercase only, through `iacrypto.DecodeHex`. That includes
  reading back a recorded machine identity (`ParseMachineIdentity`), a value
  compared as text, which is written in lowercase.
- **Counts:** lowercase hex with no leading zeros (`"0"` is zero), no larger
  than the reader can hold. keri-go reads the counts in an event this way and
  refuses an event with an unreadable one rather than reading it as if the
  count were missing. A sequence number the core reads itself goes through
  `iacrypto.ParseHexCount`; `witnessproto`, which stands alone, applies the
  same rule and refuses a JSON number.
- **Whitespace** is not part of any spelling. A key or signature that is
  decoded is read exactly as it arrives, and whitespace around it is
  refused. It is trimmed before decoding only where a person types the
  value: the release key given in the environment or at build time, and the
  accepted launch measurements in configuration. One key is not decoded at
  all: a controller grant's `public_key` is opaque text, compared with the
  key a request names, and spaces around it are ignored on both sides of
  every comparison, so it too has one meaning however it is padded.

**Witnesses are compared by key.** keri-go refuses to build or validate a
witness list (or a credential registry's backers) that names one witness
twice, under any spelling, or that names one by anything but a canonical
non-transferable identifier. The core counts by key and ignores a receipt
under a name that is not canonical.

A receipt counts toward an event's threshold only when it comes from a
witness designated at that event, verifies, and comes from a witness not
already counted. The designated witnesses are named at inception and
amended by each rotation; an interaction event is witnessed by the set in
force at it. The threshold is the key log's own, and a threshold of zero
needs no receipt. Every receipt route and the record check use the one
counter that does this. Where the log cannot say who the witnesses are (an
event that does not parse, or an establishment event whose witness
threshold is missing or unreadable), that event and every later one report
their threshold as not met.

## Consequences

- Within any one spelling, comparing two decoded keys, signatures or counts
  as text gives the same answer as comparing their bytes. None can be counted
  twice, stored twice, or slip past a duplicate check by being respelled.
- Everything this implementation, keri-go and keripy write is already in the
  accepted string, so nothing they produce stops reading. That was checked
  producer by producer: keys and signatures are written by the qb64 encoders
  and `RawURLEncoding`, update manifests by `EncodeBase64URL`, an app's call
  key by `appcall.EncodeKey`, hex by Go's
  `hex.EncodeToString`, and counts by keri-go and keripy, all of which write
  the canonical form.
- A value written in a non-canonical string by some other producer is refused.
  That includes a stored record. The producer has to write the canonical form.
- Another implementation that checks keys, signatures or counts received
  from this one can rely on getting exactly one string for each.
