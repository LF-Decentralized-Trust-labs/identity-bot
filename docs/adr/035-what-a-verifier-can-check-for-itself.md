# ADR-035: What a verifier can check for itself

**Status:** Accepted

**Date:** 2026-08-07

## The decision

**An agent running on hardware somebody else owns publishes evidence about that
hardware, and a client checks that evidence itself rather than believing it.**

Four things are checked, in this order, and each is refused rather than
downgraded:

1. **The report is signed by a genuine processor.** Its signature is verified
   against the certificate the manufacturer issued for that exact part, and that
   certificate against a manufacturer root the client already holds.
2. **The machine is running expected software.** The launch measurement in the
   report equals one the client accepts.
3. **The report belongs to this connection.** `REPORT_DATA` is recomputed from
   the fingerprint of the certificate on the connection in use, so a genuine
   report cannot be replayed onto a connection somebody else terminates.
4. **The guest is not debuggable.** A report can be genuine, chain correctly and
   carry the expected measurement while describing a guest whose memory the host
   may read.

A client that cannot complete all four reports that it could not check, never
that the machine is unverified. Those are different facts and only one of them
is safe to act on.

## Why the client and not the machine

The evidence was previously produced and checked by the same machine. That is
the wrong way round: the party who needs convincing was the one doing no
checking, and a machine's own account of itself is an assertion however well
formatted.

It also has to be checkable **before** trusting, which rules out anything that
requires already being the owner. A client verifies a machine in order to decide
whether to trust it; if the evidence needed an owner's key, then by the time you
could ask you would already have trusted the thing you wanted to check. So the
evidence is public, and its publication is a decision rather than an oversight —
what it contains is the same for every instance of an image, names the processor
rather than any tenant, and includes no identifier.

## What each check actually establishes

**The chain** establishes that some genuine part produced this report. It says
nothing about which machine or whose.

**The measurement** establishes what was launched: firmware, kernel, initial
filesystem and the launch arguments. It is the same value for every instance of
the same image, so it identifies software rather than an instance.

**The binding** is what makes the other three about *this* conversation. Without
it a report is a true statement about some sealed machine somewhere, which any
operator could obtain and present.

**The debug flag** is the one most easily forgotten, because everything else
about such a report is valid.

## The limit, stated plainly

**The measurement is only as good as the reader's knowledge of which measurement
is correct.**

Everything above can be verified by a stranger with no relationship to whoever
runs the hardware — the certificate chain terminates at a manufacturer root, and
the signature either verifies or does not. That is genuinely checkable.

Deciding **which measurement should be accepted** is not, today. A client
compares against a set it was given, and nothing in this repository lets a reader
compute what that set ought to contain. A verifier can therefore establish "this
is a genuine sealed machine running software with measurement X" entirely for
itself, and must then take somebody's word that X is the right answer.

That is the single step the guarantee rests on and the single step that is not
independently checkable. It is recorded here rather than left for a reader to
discover, because a verification story with an unmarked gap is worse than one
with a marked gap: the first invites trust it has not earned.

Two things would close it, and both are needed:

- **A reproducible build**, so that the same source produces the same bytes and
  therefore the same measurement, for anybody who builds it.
- **A published recipe**, so that somebody who has never seen our infrastructure
  can perform that build and compare.

Until both exist, clients should treat an accepted measurement as a statement
about who they trust to tell them, not as something they have verified.

## What this does not address

**Traffic.** Verifying the machine says nothing about who can read what travels
to it. An agent may be provably sealed and still be reached through something
that terminates its transport.

**Rollback.** Nothing here stops an operator presenting an older image whose
measurement was once accepted. Preventing that needs a counter an operator
cannot rewind, which is a hardware property this does not assume.

**A compromised guest.** All four checks concern how the machine was launched.
Software that was correct at launch and is later exploited still measures
correctly.

## Consequences

A client can refuse a machine for four distinct reasons and must report them
distinctly — "could not check" and "checked and failed" call for opposite
responses, and collapsing them into one boolean means the first gets treated as
the second.

An agent must serve this evidence without authentication, and must therefore
carry nothing identifying in it.

Publishing the measurement set becomes a trust-bearing act rather than an
operational one. Whoever publishes it is asserting what customers should accept,
and that assertion deserves the same scrutiny as a signing key.
