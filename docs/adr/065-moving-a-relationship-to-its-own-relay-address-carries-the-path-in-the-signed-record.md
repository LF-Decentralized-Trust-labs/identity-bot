# ADR-065 — Moving an earlier relationship to its own relay address: the signed record carries the path

**Summary:** To move a relationship made before addresses were per relationship, the endpoint record gains a signed `path` (a new record type), rather than every private address becoming its own host name.

**Status:** Proposed
**Date:** 2026-11-05
**Relates to:** ADR-062 (An address is believed only when its owner signed it), ADR-048 (One relay protocol), ADR-036 (A computer you pair with does not publish who you are), ADR-060 (A key or signature has one accepted string per spelling), ADR-033 (An identifier travels with an address)
**Amends (if accepted):** ADR-062 §1 (a second record type, `endpoint-record/2`) and its "Not covered: a path prefix"; ADR-048 §9 and its "Moving a relationship made before addresses were per relationship"

## Context

A new pairwise relationship is given a private relay address of its own (ADR-048,
"Built in the core, per relationship"). A relationship made earlier keeps the one
shared address, so its counterparty and every other such counterparty still see
the same path at the same relay.

Moving an earlier relationship means telling its counterparty a new address, and
the counterparty must believe it. The only thing it believes is an endpoint record
signed by the identifier's own key (ADR-062). That record names an origin,
`scheme://host:port`, and nothing after it. A private address is a path at the
relay (ADR-048 §8: `https://<relay>/<label>`). So the record can say which relay,
not which address on it.

**The decision asked for:** how the new address reaches the counterparty.

- **(a)** The record carries a path.
- **(b)** Each private address is its own host name (`<label>.<private-relay>`),
  served by a wildcard name and certificate at the relay, and the record is
  unchanged.

## Decision (proposed): (a)

**A new record type, `endpoint-record/2`, adds one signed string, `path`.**

1. **The record.** Six strings: `type` (`endpoint-record/2`), `aid`, `origin`,
   `path`, `issued`, `signature`. Everything in ADR-062 §1 holds for the other
   fields. `signature` is over the other five in ADR-049's form, with `path` on its
   own line after `origin`.
2. **One spelling of a path (ADR-060).** `path` is empty, or `/` followed by one
   or more segments joined by `/`, each 1 to 63 characters of `a-z`, `0-9` and
   `-`. No trailing slash, empty segment, `.` or `..` segment, percent-encoding,
   query or fragment; at most 128 bytes. Anything else is refused, never
   normalised. An empty path is the address ADR-062 already names.
3. **Where requests go.** A counterparty sends an agent route to
   `origin + path + route`. The relay removes `/<label>` and adds
   `X-Forwarded-Prefix` as it does now (ADR-048 §8); no relay changes.
4. **Ordering is ADR-062's, across both types.** One record per identifier,
   replaced only by one issued strictly later, whichever type either is. A
   `/1` record reads as a `/2` record with an empty path. A reader keeps the
   newest verified record, so a witness cannot walk it back from a path to the
   shared address, nor from the shared address to an older path.
5. **Who signs.** The relationship's own pairwise identifier, with its current
   key, as ADR-062 requires. No other key may move it.
6. **Request signing is unchanged.** `X-IA-Controller-Origin` still names an
   origin. Every private address of one relay shares the relay's origin, and the
   agent already accepts its relay's origin (ADR-062 §4).
7. **The old address is not withdrawn by the move.** Nothing tells the agent a
   counterparty has moved, so the shared address keeps answering for every
   relationship that still uses it. Giving it up is the owner's call, later.

## What the counterparty checks

Everything ADR-062 §3 has it check (signature against the identifier's verified
key log, brought up to date first; newer than what it holds; not more than ten
minutes ahead), plus that `path` is in its one spelling and is covered by the
signature. A counterparty that does not know `/2` refuses the record as an
unknown type and keeps the address it has. That is safe, because the shared
address keeps answering (7); it is also why the move cannot be reported as done.

## Replay and rollback

The signed `path` is inside the signature, so a witness or proxy cannot attach one
to a record, change it, or strip it. Replaying an older `/2` or `/1` record is
refused by the ordering in (4). The residual case is unchanged from ADR-062: a
reader that has never seen the newer record can be shown an older one that the
identifier really signed, and a host that lapses while the key log stands still
is answered by a newer record or a withdrawal, not by the clock.

## What the relay operator learns

Nothing new. It already sees every label arrive down one session and can link
them (ADR-048 §11); a path is the label it already routes by. The record goes to
witnesses, not through the relay. A new path crosses TLS, so a network observer
sees the relay's name and not the label.

## Cost and deployment

- **Relays already running: no change.** They serve `/<label>` paths today.
- Code: record type, reader and checker in the core, the Dart reader
  (`endpoint_record.dart`), `check_endpoint_record_vectors.py` and the vectors
  file (new records, path spellings, ordering across types). One type to add, in
  every place ADR-062's record is read; all of them in one change (§7a).
- It also closes ADR-062's "a path prefix" gap: an agent mounted under a prefix
  becomes findable by its full address.
- Agents and apps update on their own schedules, so writing `/2` before readers
  know it moves nobody. Readers ship first, writers a release later, as in
  ADR-062's rollout.

## Rejected: (b) each private address is its own host name

It keeps the record as it is, and a host-per-address is a cleaner origin for
signing. It is rejected because:

- **Every running relay must change first:** a wildcard DNS name, and a wildcard
  certificate, which is issued by a DNS challenge. The relay then holds DNS
  credentials and one key that stands for every address on it. A certificate per
  address would put each label in public certificate logs, which is why it must
  be a wildcard.
- **It shows the label to the network.** The label becomes a DNS query and a TLS
  server name that a resolver or an observer on either side can read. A path is
  inside TLS.
- It changes ADR-048 §8 (the address form), the relay's routing, and the origins
  an agent accepts, for every relay and agent, where (a) changes one record type.

Its one advantage is that it needs no new record type, and that a request signed
for an origin would name one relationship's address. Neither outweighs the above.

## What a person sees

Nothing is asked of them. An owner sees, in reachability settings, one line while
earlier contacts are being moved ("2 contacts still share one address") and none
once they are done; contacts whose app has not updated stay on the shared address
and the line says so. The owner never sees a path or a label. A contact sees
nothing: their agent switches in the background and falls back to the address it
had if the new one does not answer.

## Not decided here, and to check

- **Where a pairwise identifier's record is published.** ADR-062's witness stores
  a record only for an identifier whose key log it holds; whether and where a
  pairwise identifier's key log is witnessed is not stated in ADR-036 or ADR-062.
  If it names no witness, the record has to reach the counterparty another way,
  and that is a question for this ADR to settle before it is accepted.
- **When the shared address is given up** (7).
- Superseded-claims entry: ADR-062's sentence that a record "names an origin and
  nothing after it" becomes false for `/2`; it is registered in the change that
  accepts this.
