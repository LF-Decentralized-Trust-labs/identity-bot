# ADR-060 — A key or signature has one accepted string per spelling

**Status:** Accepted
**Date:** 2026-10-31
**Relates to:** ADR-015 (Mobile KERI service architecture, whose receipt routes report `threshold_met`), ADR-049 (One signing form for every service provider request)

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

**Line breaks.** Standard base64 decoders skip `\r` and `\n` anywhere in the
string.

**Hex case.** `50d858e0…` and `50D858E0…` are the same bytes.

**Counts.** A KERI event writes counts (`s`, `bt`, and `kt`/`nt` when they are
a number) in hex, and `"2"`, `"02"` and `"002"` read as the same number.

## Decision

**Every value is read in exactly one string for each spelling it may arrive
in.** A string that only a lenient decoder would read is refused.

- **qb64** (keys, identifiers, signatures, indexed signatures): the exact
  length for its code, base64url only, and every lead bit zero. This is the
  form keripy and keri-go both write. `iacrypto.DecodeQB64` reads it, and
  keri-go reads every CESR value the same way.
- **Raw base64 where a format names unpadded base64url** (signatures on
  DIDComm messages, activity log records, hardware-signer attestations, URL
  relay admissions): only that alphabet, no padding, no line breaks, and zero
  spare bits. `iacrypto.DecodeBase64URL` and `DecodeBase64URLSized` read it.
- **Raw keys in a field that accepts more than one base64 spelling** (because
  different languages write different ones): each of the four spellings
  (base64url or standard alphabet, padded or not) is read strictly, at the
  exact size, with zero spare bits and no line breaks. `iacrypto.DecodeSized`
  reads it. A key may still arrive in more than one of those spellings, so
  code that compares keys from such a field compares the decoded bytes, never
  the text.
- **Hex:** lowercase only.
- **Counts in a KERI event:** lowercase hex with no leading zeros (`"0"` is
  zero). An event with an unreadable count is refused, not read as if the
  count were missing.

**Witnesses are compared by key.** A witness list that names one witness
twice, under any spelling, is refused. A receipt counts toward an event's
threshold only when it comes from a witness that event names, verifies, and
comes from a witness not already counted. If a key log's witness threshold
cannot be read, the event reports its threshold as not met.

## Consequences

- Within any one spelling, comparing two values as text gives the same answer
  as comparing their bytes. A value cannot be counted twice, stored twice, or
  slip past a duplicate check by being respelled.
- Everything this implementation, keri-go and keripy write is already in the
  accepted string, so nothing they produce stops reading.
- A value written in a non-canonical string by some other producer is refused.
  That includes a stored record. The producer has to write the canonical form.
- Another implementation that checks values received from this one can rely
  on getting exactly one string per value.
