# Statement signature (v1)

A utility app's signed-in page can ask a person to sign a statement with their own Identity Agent (Ask action 6, `sign_statement`, see
[action-code-registry.md](action-code-registry.md) and [ADR-080](adr/080-a-person-signs-a-statement-an-app-hands-them-with-their-own-identity-agent.md)).
This is the format of the statement, of the bytes that are signed, and of the rules the person's Identity Agent
applies before it shows or signs anything. Anyone who builds such a statement or verifies such a signature needs it,
so it is open and has byte-exact vectors:
[`identity-agent-core/statements/testdata/vectors.json`](../identity-agent-core/statements/testdata/vectors.json),
run by the core's tests (`identity-agent-core/statements`) and by every consumer that builds or checks statements.
**Consumers pin the vectors; they never copy them.** A change to a vector, or to any builder or reader that no longer
produces the same bytes, fails the tests of every consumer.

## The statement

UTF-8 text, lines separated by `LF` only, no trailing line break. At most 2048 bytes and 24 lines.
The first line is a header, `<name>/<version>`: `name` is lower-case letters, digits and hyphens, beginning with a
letter (at most 63 characters), and `version` is one to four digits. A header no key event can begin with (events begin
with `{`), so a signature of a statement can never be read as a signature of a key event or a credential.

Refused, before anything is shown: a control character other than `LF`, a line or paragraph separator, a bidirectional
override or isolate mark, a zero-width character, a statement that is not valid UTF-8, one over the limits, one that
ends with a line break, one whose first line is not a header.

## What is signed (the envelope)

    statement-signature/1\n
    asker: <the asker's identifier>\n
    \n
    <the statement, exactly as shown>

The asker's identifier is the site identifier of the Ask the person answered, so a signature made for one verifier is
refused by another. The signature is Ed25519 over those bytes by the signer's root key in force, written as a CESR
indexed signature (derivation code `A`, index 0, so it begins `AA`; 88 characters).

A verifier holding the signer's key history takes the key at the sequence number `kel_sn` that came with the signature
(the sequence number of the latest establishment event, interaction events counted), requires it to be at or after the
latest inception or rotation, and checks the signature over the envelope it rebuilds itself.

What the envelope does not carry is a nonce. The nonce protects the round trip between the asker and the person's Identity
Agent. A statement must therefore say what it is for (a decision's id and a hash of its sentence, say) so that a
signature of it cannot be moved to another purpose.

## A statement made unasked

An Identity Agent may sign a statement nobody asked it for: a statement about something of its own, which it hands
out itself. The envelope is the same. The `asker` line then carries the **signer's own identifier**: nobody asked, so
the signer names itself as the one the statement is made for.

That calls for two rules in whatever answers an Ask, so that a statement made unasked can never be obtained by
asking. Both are **proposed here, and not yet enforced**:

- an Identity Agent answering an Ask **refuses a statement whose asker is the signer's own identifier**;
- an Identity Agent answering an Ask **refuses a statement whose header is reserved** for statements made unasked.

The reference Ask handler does not enforce either yet. It is safe today only because an asker is another identity's
site identifier, and enforcing both there is a change of its own.

**Reserved headers.** A reserved header is not a display form: a statement that carries one is never shown to a
person to sign.

| Header | What it is |
|---|---|
| `set-up-seal/1` | An Identity Agent's seal on a file its set-up was exported to ([set-up-file.md](set-up-file.md), ADR-088). Three lines: the header, `contents=<the digest of the file's contents>`, and `kel-sn=<a whole number in decimal>`. |

**The sequence number of a seal.** A seal travels in a file, with no round trip to carry `kel_sn` beside it, so the
sequence number is inside the statement and is signed. A verifier takes the key the signer's key history names at
that sequence number, which must be an establishment event, and reports whether that event is still the latest
establishment event: a seal by a key the signer has since replaced is reported as that, and never as a seal that
holds. A signer whose key state at that event holds more than one key is not supported by version 1 of the seal.

## Registered display forms

A form is a header a person's Identity Agent knows how to read, so it can show the statement more clearly. A form changes
how a statement is shown and never whether it can be signed; a statement whose header is not registered is signed shown as
text.

### `decision-approval/1`

Seven lines, in this order, nothing else:

    decision-approval/1
    decision=<number>
    title-hash=<BLAKE3-256 of the decision's sentence, CESR E>
    decided-by=<who decided it>
    impact=small|moderate|architectural
    undo-minutes=<number>
    verdict=approve

The sentence the hash is of may be sent with the Ask (`title`); it must hash to `title-hash` and be one line of at most
600 characters, or the statement is refused. What the person sees is built only from the checked statement and the
checked sentence. Without a sentence the person sees the hash, not text nobody checked.

`disagreement/1` is a statement the generic rules cover; it has no display form yet and is shown as text.
