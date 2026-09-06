# ADR-040 — The protocol's deep-link namespace is vendor-neutral

**Status:** Accepted
**Date:** 2026-09-06
**Relates to:** ADR-006 (Standardized Topology), ADR-036 (A computer you pair with does not publish who you are)

## Context

A controller offers itself to an owner as a self-contained code the owner scans:
a signed statement that this machine may act for an identity, carried whole in a
QR rather than fetched from a pointer. That code needs a namespace — a URI scheme
so a scanner can tell one of the protocol's own codes from anything else a camera
sees, and a domain-separation prefix inside the signed bytes so a controller
*offer* can never be replayed as a controller *request*.

Neither had ever been architected. The scheme and the prefix were introduced
ad-hoc alongside the first controller offer, and the first draft named both after
a vendor. That is wrong for two reasons. The scheme is the protocol's public wire
namespace, minted into every offer link a conforming implementation emits. The
prefix is worse: it is inside the bytes every implementation must sign and rebuild
to verify, so it is part of the interoperability contract itself — an independent
implementer would be forced to emit a vendor's token to interoperate at all. This
is the reference implementation of a **vendor-neutral** protocol; a brand in
either place makes the neutral core emit branded links and bakes a vendor into the
wire format.

These namespaces are also not routed by any operating system. Nothing registers a
handler for them; the application builds the code, shows it, scans it, and parses
it against its own constant. So the choice is free of OS-registration constraints,
and — because the offer code is unreleased — free of any compatibility cost, which
is exactly why it is settled now rather than after adoption.

## Decision

The protocol's deep-link / QR namespace is **vendor-neutral**, named for the
protocol:

- **Scheme:** `identity-agent://` — e.g. a controller offer is
  `identity-agent://controller?…`. RFC 7595 discourages vendor scheme names and
  favours descriptive ones; this follows that. A commercial build layered on this
  core MAY override the scheme it displays for its own registered handler, but the
  neutral name is what the reference implementation emits, and it is a single
  constant so an override is one substitution.
- **Signed domain-separation prefix:** `identity-agent-controller-offer-v1` — the
  first line of the exact string a controller signs and an owner rebuilds to
  verify. Because it is on the wire and part of what every implementation must
  agree on, it is fixed and neutral, and NOT overridable.

Future protocol codes in this namespace inherit the neutral scheme.

## Consequences

- A third party running this reference implementation emits neutral
  `identity-agent://…` links and signs neutral offer bytes; nothing forces a
  vendor's name into the protocol.
- The scheme lives as one constant in the offer service, so a downstream product
  that wants to show its own branded scheme changes one value; the signed prefix
  does not move.
- This namespace is documented here rather than left ad-hoc, so later deep-link or
  QR codes have a settled, neutral home to extend.
