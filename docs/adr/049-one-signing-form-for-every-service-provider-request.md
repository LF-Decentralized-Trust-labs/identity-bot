# ADR-049 — One signing form for every service-provider request

**Status:** Accepted
**Date:** 2026-10-21
**Amends:** ADR-024 (the signing form of relay and mailbox requests)
**Relates to:** ADR-048 (One relay protocol: a public or private address, admitted by signature)

## Context

An Identity Agent signs requests to the services it uses, so a service can tell
which identifier asked without being able to ask in its name: an admission to a
relay, a relay control request, a request to a mailbox. Each signature is over a
byte form of the request, and a verifier has to rebuild exactly those bytes.

Three copies of that form grew up, and they did not agree. One escaped `<`, `>`
and `&` the way Go's JSON writer does by default. One did not. One accepted
numbers, lists and nested objects, whose spelling (`1` or `1.0`, the order of a
nested object's keys, how a non-ASCII character is written) differs between
JSON writers. A request with an ampersand in a URL, or a number in it, verified
in one implementation and not in another, and nothing said which form a new
implementation was meant to produce.

## Decision

**Every signed request to a service provider is signed over one form: the
request's fields as a JSON object, keys sorted, no whitespace, no HTML escaping,
and the `signature` field left out.** `relayproto.CanonicalBody` in this
repository is that form.

1. **Every field is a string of printable ASCII**, keys included (bytes 0x20 to
   0x7E). Anything else is refused, never signed. That is what makes the form
   the same in every language: a JSON writer that does not escape HTML writes
   such a string one way only.
2. **Keys sort by byte value.** Upper case before `_` before lower case.
3. **A request carries what it signs as strings.** A count is a decimal string
   (`"limit": "50"`). A list is one string with its items separated by single
   spaces (`"message_ids": "m-1 m-2"`). A field that cannot be written that way,
   such as a message being delivered, is not signed by the sender; it is
   carried beside the signed fields.
4. **The signature is Ed25519 over those bytes**, by the key the identifier's
   key event log names now, written base64url without padding.

The relay's admission statement and control requests (ADR-048 §3, §8) and the
mailbox's signed requests use this form.

## Contract

`identity-agent-core/relayproto/signing-vectors.json` holds the requests, the
bytes each is signed over, and a signature over each by a fixed key, plus inputs
that must be refused. An implementation in another language reproduces every
`canonical` from its `fields` and every `signature` from the seed. A Go
implementation reads the same file through `relayproto.SigningVectors()` rather
than keeping a copy.

## Consequences

- One form to implement and to test against, published with vectors.
- A service's request shapes are constrained to string fields. A protocol that
  signed a number or a list changes its wire format to carry it as a string.
- Changing the form means changing the vector file, which fails this
  repository's tests first.
