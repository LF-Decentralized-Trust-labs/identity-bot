# ADR-062 — An address is believed only when its owner signed it

**Status:** Accepted
**Date:** 2026-11-04
**Relates to:** ADR-033 (An identifier travels with an address), ADR-042 (Reachability), ADR-048 (One relay protocol), ADR-031 (Who witnesses what), ADR-049 (One signing form for every service provider request), ADR-060 (A key or signature has one accepted string per spelling)
**Amends:** ADR-048 §9 (the published record is this one, not a KERI `rpy`), ADR-033 (`PublishEndpointLocation` signs `endpoint-record/1` where it sent a `/loc/scheme` reply), ADR-042 §3 (the 2026-11-02 line that the signed string does not change: a controller's request has a third form, `IA-CONTROLLER-REQ-V3`)

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
   - **A record does not expire by the clock.** A record is believed while the
     key that signed it is the identifier's current key and while no newer record
     has been seen. Any rotation ends it, because the checker holds the identifier's
     verified key log and a record signed by a replaced key is refused; and an
     older record than one already verified is refused, so a witness cannot walk
     a reader back. An age limit was rejected as the default: it would make an
     identifier that never moves unfindable after the limit, for a host that has
     not lapsed. Tying each record to the key-log event it was signed under was
     not taken either: it says nothing about a host that lapsed while the key log
     stood still, and it would change the signed form. A verifier may still set a
     maximum age (`VerifyNoOlderThan`, `verifyEndpointRecord(maxAge:)`); nothing
     in this repository does, and the contract carries it as an option
     (`max_age_days`) that a vector states when it applies.
   - `signature` is Ed25519 over the other four fields in ADR-049's form, as a
     CESR qb64 signature (code `0B`, ADR-060).
   - The signer is the key the identifier's verified key log names now, so a
     rotation is followed and a record signed by a replaced key is refused. A
     record carries no key and no delegation. **One key**: the key is the first of
     the log's current key set, as everywhere in this agent; a log whose current
     keys need several signatures to act is not supported, and a record is judged
     against its first key alone.
2. **The witness.** `POST /api/witness/endpoint` and
   `GET /api/witness/endpoint/{controller_aid}` are open to anybody. The route
   stores a record only for an identifier whose key log the witness holds and
   verifies end to end, only in the form above, only when signed by that log's
   current key and newer than the record held, and keeps that one record in
   place of the last. Every refusal that depends on the key log (no log held,
   a record that does not verify) is the same 403, as the key log reads answer
   a log not held, so the route does not say which identifiers this witness
   holds a log for to somebody who has nothing signed by the identifier. A
   genuine record for an identifier this witness holds is answered 200 (or 409 if
   an equal or newer one is held), and for one it does not hold, 403. That
   difference is accepted: it can be seen only by somebody holding a record the
   identifier signed with its current key, and an identifier's key log names its
   witnesses (the `b` field of its events), so such a party can already read
   which witnesses it uses. The witness checks a key log once per log (a digest
   of every event and signature held), not once per request. The read returns the newest record as it was signed, and
   the same 404 whether the identifier is not witnessed or has no record.
3. **The reader.** A witness holds no authority. Whoever reads a record checks it
   against the identifier's own verified key log, never against a key the
   record or the witness brings; without a verified log nothing is believed.
   Before it checks, it brings the identifier's key log up to date: it asks the
   witnesses for the events after the last one it holds (proving the read with the
   inception event, as the other key log reads do) and keeps the longer log only
   when the whole of it verifies, so a rotation made since the identifier was
   last resolved is followed. It asks every witness the identifier names, takes the newest record that
   verifies, treats a withdrawal as outranking the addresses before it, and
   keeps the newest it has verified, so that no witness, however stale or
   hostile, can take it back to an older address the identifier really did
   sign.
4. **The request.** A controller's signed request may name the origin it is sent
   to. It is then signed in a third form, `IA-CONTROLLER-REQ-V3`, with the
   origin on its own line after the Identity Agent, carried in
   `X-IA-Controller-Origin`. The Identity Agent refuses an origin that is not
   one of its own: its relay, tunnel, configured public URL or
   loopback. It does not compare against the `Host` header, which the forwarder
   chooses. The form differs from the second, so removing the header leaves a
   string the request was not signed over. An origin that is present and not in
   its one spelling is refused, never read as absent.

   **The agent's own origins come only from what it was configured with**, never
   from anything a request says: `PUBLIC_URL`, an explicit override, its relay and
   tunnel and loopback. *(Amended 2026-11-05: `AGENT_DIRECT_INGRESS_ADDR` is gone, and the direct listener's address is not an origin: see the note at the end.)* The address a trusted proxy
   reported (`TRUST_FORWARDED_HEADERS`) is still used for the address the agent
   publishes, but it is not an origin the agent accepts a request for: a front
   proxy that appends to `X-Forwarded-Host` instead of replacing it would
   otherwise let a hostile proxy make its own address "ours".

   A request that names no origin is still read in the second form during the
   rollout below.

## The rollout, in four steps

Agents and apps update on their own schedules (in the individual app the agent
and the controller are separate programs), so no pin order makes a one-step change
safe: an app that signs the origin is refused by an agent that has not learned to
read it, and an agent that requires an origin refuses an address it was never told
about. A refused request is **never** retried in the older form: the refusal is a
status a hostile proxy could fake, and the retry would be the downgrade.

a. **This change.** The agent accepts both forms, and a request that names no
   origin is read in the second form. The Dart client
   (`ControllerSigningClient.signsTheOrigin`) sends the origin only when that
   setting is on, and it is off by default. The witness routes and the reader's
   checks are as above. Nothing a deployment does changes.
b. **Configure the addresses.** Before step c every agent must be told every
   address it is reached at, and the settings that do it are:
   - `PUBLIC_URL` (or an explicit override) for an agent behind a reverse proxy,
     a domain or a custom name: the origin the app dials. Needed by any
     deployment reached by name.
   - ~~`AGENT_DIRECT_INGRESS_ADDR` for an agent reached on a LAN address or a
     mapped Docker port~~ *(withdrawn 2026-11-05: see the note at the end. An agent
     that still sets it refuses to start. Management of such an agent goes through
     `PUBLIC_URL` or a relay.)*
   - A sealed instance behind its own proxy: the proxy's public origin as
     `PUBLIC_URL`.
   - Relay and tunnel addresses need nothing: the agent knows them. Loopback needs
     nothing.
   - `TRUST_FORWARDED_HEADERS` does **not** do this and must not be relied on to.
   An agent without the right setting answers 403 to a request signed for an
   address it does not list. Check with `REQUIRE_CONTROLLER_ORIGIN=1` on a test
   instance before step c.
c. **The apps turn origin-sending on** (`signsTheOrigin: true`), in a release after
   every agent they reach is at step a and configured as in step b.
d. **The agent requires the origin.** In the release after step c the default of
   `REQUIRE_CONTROLLER_ORIGIN` becomes on and the no-header path (the second form)
   is removed. Until then an operator may set it earlier. A request in the second
   form is then refused, as it is by any agent already configured so.

## Not covered

- **A path prefix.** A record names an origin and nothing after it, because a
  request is signed for an origin and a deployment's mount path is layout, not
  identity. An agent mounted under a prefix (for example behind
  `X-Forwarded-Prefix`) is therefore findable by host but not by the full address
  it published before; a counterparty reaches its agent routes under its own
  configured prefix. Keeping the prefix needs a new record type, because the
  signed fields would change; it is left for one.
- **Renewal.** There is none to do: a record stands until the identifier
  rotates its key or publishes a newer one (see "A record does not expire by the
  clock"). The core publishes when an address changes and does not re-sign on a
  schedule. What this leaves open is a host that lapses or changes hands while
  the identifier's key log stands still and no new record is published: the old
  record keeps pointing there. The identifier's answer is to publish a
  withdrawal or a new record, and a reader's is the age limit above.

## Contract

`identity-agent-core/endpointrecord/endpoint-record-vectors.json` holds records,
the bytes each is signed over, whether each verifies and why not (including one
signed by a key since rotated away from, and one older than a limit a verifier sets), the origins
that are in their one spelling and those that are not, which of two records
replaces the other, and the strings a controller signs for a request in the
second and third forms. `check_endpoint_record_vectors.py`, beside it, rebuilds every
verdict and every request string from this ADR's text in Python, and the package's tests run it where Python and its `cryptography` module are installed (skipped, with a message saying what is missing, where not).
`packages/agent_client/lib/crypto/endpoint_record.dart` reads the same file in
its tests and decides every vector the same way.

## Consequences

- **Agents ship before apps.** An app that signs the origin is refused by an
  Identity Agent built before this: the old agent ignores the header and checks
  the older string. The grace runs only the other way, for an old app against a
  new agent. Hence the four steps above.
- **An agent behind a public address must know it.** The Identity Agent accepts
  only the origins it was configured with: a public URL, its relay or tunnel,
  the address it serves directly, and loopback. An app reaching it through a
  reverse proxy whose address the agent was never told is refused until the
  address is configured (step b).
- A record signed for one origin cannot be made to name another, and a witness or
  proxy cannot supply one the identifier did not sign.
- An identifier that rotates its key publishes its record again.
- A client that has not been updated to send the origin keeps working until the
  origin is required; until then a request it signs can still be relayed.

**Amended 2026-11-05 — no direct address among the agent's own origins.** The
whole-surface hatch `AGENT_DIRECT_INGRESS_ADDR` was removed with the second
listener (ADR-042 §2). The direct listener (`AGENT_DIRECT_LISTEN_ADDR`) serves
public identifier documents only and carries no management traffic, so a
controller never signs a request for it and its address is not one of the
agent's own origins (`EndpointService.OwnURLs`). Rollout step b no longer lists
`AGENT_DIRECT_INGRESS_ADDR`; an agent started with it set refuses to start and
names the variable. A deployment that was reached for management on a LAN
address or mapped port sets `PUBLIC_URL` to that address, which keeps it an
origin of the agent.
