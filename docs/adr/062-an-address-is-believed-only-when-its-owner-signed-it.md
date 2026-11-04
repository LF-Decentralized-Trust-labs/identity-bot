# ADR-062 — An address is believed only when its owner signed it

**Status:** Accepted
**Date:** 2026-11-04
**Relates to:** ADR-031 (Who witnesses what), ADR-049 (One signing form for every service provider request), ADR-060 (A key or signature has one accepted string per spelling)

## Context

A computer that is told an organisation has moved, and goes to the new address,
can be led anywhere by a plain reverse proxy: the proxy answers at an address
of its own, relays what it is sent to the real organisation, and relays the
answers back. Nothing in the answers shows the address does not belong to the
organisation.

Two things were missing. A witness kept an identifier's endpoint record without
checking any signature on it, so it could not be opened to anyone, and a
counterparty with a dead address had no public way to ask a witness for the
current one. And a request a controller signed named the Identity Agent it was
for but not the address it was sent to, so a copy relayed through any host
verified.

## Decision

**An address is believed when the identifier it belongs to signed it.**

1. **The record.** An endpoint record is five strings: `type`
   (`endpoint-record/1`), `aid`, `origin`, `issued` and `signature`.
   - `origin` is the exact origin, `scheme://host:port`, in one spelling:
     scheme `http` or `https`, host in lower case, port always written, nothing
     after it. A host that ends in a number (`127.1`, `2130706433`, `0x7f.1`) is
     refused unless it is four decimal numbers without a leading zero, because a
     resolver reads each of those as another spelling of one address. An empty
     origin says the identifier is reachable nowhere.
   - `issued` is `YYYY-MM-DDTHH:MM:SSZ`, UTC. A record replaces another only
     when issued strictly after it; an older or equal one is refused. A record
     issued more than ten minutes ahead of the checker's clock is refused.
   - `signature` is Ed25519 over the other four fields in ADR-049's form, as a
     CESR qb64 signature (code `0B`, ADR-060).
   - The signer is the key the identifier's verified key log names now, so a
     rotation is followed and a record signed by a replaced key is refused. A
     record carries no key and no delegation.
2. **The witness.** `POST /api/witness/endpoint` and
   `GET /api/witness/endpoint/{controller_aid}` are open to anybody. The route
   stores a record only for an identifier whose key log the witness holds and
   verifies end to end, only in the form above, only when signed by that log's
   current key and newer than the record held, and keeps that one record in
   place of the last. Every refusal that depends on the key log (no log held,
   a record that does not verify) is the same 403, as the key log reads answer
   a log not held, so the route does not say which identifiers this witness
   holds a log for. The read returns the newest record as it was signed, and
   the same 404 whether the identifier is not witnessed or has no record.
3. **The reader.** A witness holds no authority. Whoever reads a record checks it
   against the identifier's own verified key log, never against a key the
   record or the witness brings; without a verified log nothing is believed.
   It asks every witness the identifier names, takes the newest record that
   verifies, treats a withdrawal as outranking the addresses before it, and
   keeps the newest it has verified, so that no witness, however stale or
   hostile, can take it back to an older address the identifier really did
   sign.
4. **The request.** A controller's signed request may name the origin it is sent
   to. It is then signed in a third form, `IA-CONTROLLER-REQ-V3`, with the
   origin on its own line after the Identity Agent, carried in
   `X-IA-Controller-Origin`. The Identity Agent refuses an origin that is not
   one of its own: its relay, tunnel, configured public URL, direct address or
   loopback. It does not compare against the `Host` header, which the forwarder
   chooses. The form differs from the second, so removing the header leaves a
   string the request was not signed over. An origin that is present and not in
   its one spelling is refused, never read as absent.

   A request that names no origin is still read in the second form for one
   version, as `X-IA-Body-Digest` was; the Identity Agent can then be made to
   require the origin, and the no-header path is removed.

## Contract

`identity-agent-core/endpointrecord/endpoint-record-vectors.json` holds records,
the bytes each is signed over, whether each verifies and why not, the origins
that are in their one spelling and those that are not, and which of two records
replaces the other. `check_endpoint_record_vectors.py`, beside it, rebuilds every
verdict from this ADR's text in Python, and the package's tests run it.
`packages/agent_client/lib/crypto/endpoint_record.dart` reads the same file in
its tests and decides every vector the same way.

## Consequences

- **Agents ship before apps.** An app that signs the origin is refused by an
  Identity Agent built before this: the old agent ignores the header and checks
  the older string. The grace runs only the other way, for an old app against a
  new agent.
- **An agent behind a public address must know it.** The Identity Agent accepts
  only the origins it knows are its own: a configured public URL, its relay or
  tunnel, the address it serves directly, and loopback. An app reaching it
  through a reverse proxy whose address the agent was never told is refused
  until the address is configured. The address a trusted proxy reported
  (`TRUST_FORWARDED_HEADERS`, the first value seen) counts, as it already does
  for the address the agent publishes.
- A record signed for one origin cannot be made to name another, and a witness or
  proxy cannot supply one the identifier did not sign.
- An identifier that rotates its key publishes its record again.
- A client that has not been updated to send the origin keeps working until the
  origin is required; until then a request it signs can still be relayed.
