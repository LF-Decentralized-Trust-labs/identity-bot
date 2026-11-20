# An Identity Agent is owned when two key logs say so (ADR-087)

How a verifier decides, from two key logs, whether an owner identity owns an
Identity Agent. This is the whole of the check, so another implementation can
be written from it. It covers decisions 1 to 4 of ADR-087 and the part of
decision 8 a verifier applies. It does not cover how a machine is founded or
how an address proves it holds a key.

Worked examples, each with the grade and reason it must give:
`../../ownership/owned-vectors.json`, checked independently by
`../check_owned_vectors.py`, which needs the `blake3` module. The Go reading
is `ownership.Check`.

Below, **M** is the identifier of the Identity Agent and **X** the identifier
of the owner identity.

## The two seals

Both are KERI's event seal, three fields in this order:

```
{"i": <identifier>, "s": <sequence number, lowercase hex>, "d": <the event's SAID>}
```

- **The owner seal** (ADR-032) is an event seal in the `a` field of an
  **establishment event** of M that names an inception: `"s"` is `"0"` and
  `"d"` equals `"i"`. It says M names that identifier as an owner. A seal in an
  establishment event with exactly these three fields and an empty `"i"` or
  `"d"` makes the log unreadable for this purpose (`log_invalid`); any other
  seal is not an owner seal.
- **The anchor** is an event seal in the `a` field of an **interaction event**
  of X that names an establishment event **E** of M: `{"i": M, "s": E's
  sequence number, "d": E's SAID}`. For the owner named at founding E is M's
  inception and the seal is `{"i": M, "s": "0", "d": M}`. An event seal in an
  establishment event of X is never an anchor: it is X's own owner seal.

**The owner set in force** at an event of M is the set named by the latest
establishment event, at or before it, that carries owner seals. A rotation that
carries none leaves the set as it was. A log whose inception carries none has
no owners at any event, whatever a later event carries.

## What the verifier is given

- M's log and X's log, each as its events in order with the controller
  signatures attached.
- For each log, where the copy came from: **its witnesses** (the log's latest
  state as its own witnesses hold it, asked for by the verifier) or **the
  checked party** (the machine, or whoever presents the pair). Not saying is
  the checked party.
- For each log, the witness receipts held for its events, and any **other
  copies** of that log the verifier holds: one it kept earlier, or one a
  watcher showed it.
- The logs of other identifiers, where X's interactions seal events of them.

The check fetches nothing.

## Two copies of one log

A copy is judged against each other copy the verifier holds, which must itself
verify in full. The two are compared from the start. Where they first hold
different events at one place:

- A **recovery rotation** is a non-delegated rotation at that place, in one
  copy, where the other copy holds only interaction events from that place to
  its end. It replaces those interaction events (ADR-075). If the copy being
  checked holds the recovery rotation, the other copy's events from that place
  on are **retired**. If the other copy holds it, the copy being checked is
  stale (`stale_copy`).
- Anything else is **duplicity**: two interaction events, two establishment
  events, or a rotation where the other copy goes on to an establishment event.

Where they never differ and the other copy is longer, the copy being checked
is stale (`stale_copy`). Where it is the shorter or the same, nothing is wrong.
A copy held by the verifier that does not verify, or is another identifier's
log, cannot be judged against (`log_unchecked`).

## The steps

The first that fails is the answer.

1. **M's log verifies in full** as KERI requires: the identifier is the digest
   of the inception, each event follows the one before by sequence number and
   prior digest, each is signed to the threshold of the key state in force, and
   each rotation reveals the keys the previous establishment event committed
   to. Otherwise `log_invalid`. It carries on from every other copy held, or
   `stale_copy`.
   M's log holds no delegated inception (`dip`), no delegated rotation (`drt`)
   and no event naming a delegator. Otherwise `delegated`: graded named, not
   owned when the owner set in force at M's latest establishment event names X,
   and refused when it does not.
2. **X is in the owner set in force at M's latest establishment event.**
   Otherwise `not_named`. **E** is the earliest establishment event from which
   X is in the owner set in force at every establishment event up to the
   latest. An owner that left and came back entered at the event where it came
   back, and an anchor of an earlier event does not count.
3. E is an event of the log just verified.
4. **X's log verifies in full**, the same way, with the same reasons.
5. *(Step 7 of the record, reported here.)* **Neither log is proven
   duplicitous** against any other copy held. Otherwise `duplicity`. It is
   reported ahead of the next two steps so that proof of duplicity is never
   shown as a missing anchor.
6. *(Step 5 of the record.)* **An interaction event of X's log seals E
   exactly**: identifier, sequence number and digest all equal. The first such
   seal, reading X's log in order, is the anchor being judged. Where there is
   none: `anchor_removed` if an interaction event retired from X's log (see
   above) sealed E exactly, and `named_not_anchored` otherwise.
7. *(Step 6 of the record.)* **The anchor is the first anchor in X's log, or
   names the same Identity Agent as the first.** An anchor, for this count, is
   an event seal in an interaction event of X whose sealed event is an
   establishment event that carries an owner seal naming X. Each event seal
   before the anchor being judged, in order, is looked up:
   - one that names M and is an anchor: the first anchor names M, and the step
     passes;
   - one that names M and is not an event of M's log, or not an anchor: skipped;
   - one that names another identifier whose log was not supplied, does not
     verify, is proven duplicitous, or does not hold the sealed event:
     `log_unchecked`;
   - one that names another identifier and is an anchor: `second_machine`;
   - one that names another identifier and is not an anchor (a delegation
     approval, for example): skipped.
8. **The anchoring event and E each carry valid witness receipts** (ADR-070)
   to the threshold their own log names.

## The grades

| Grade | Means |
|---|---|
| `owned_confirmed` | every step passes, and both copies came from their own witnesses |
| `owned_anchored` | steps 1 to 7 pass. The proof shows what was true of the copies given, which may be old |
| `named_not_owned` | M's log names X, and X's agreement is absent or no longer counts |
| `refused` | the check could not say owned or named |

Confirmed is never reported unless both copies came from their witnesses
**and** step 8 passes. A log that names no witnesses, or a witness threshold of
zero, is never confirmed. A receipt counts when it is by a witness in the list
in force at the event (the inception's `b`, changed by each rotation's `br` and
`ba`), is an indexed signature at that witness's place in the list over the
event's exact bytes, and verifies under the witness's key; each witness counts
once.

## The reason codes

One code goes with every result. Add to them; never rename one.

| Code | Grade | Means |
|---|---|---|
| (empty) | `owned_confirmed` | nothing to say |
| `not_from_witnesses` | `owned_anchored` | a copy of either log came from the checked party, which can hide a later event |
| `receipts_short` | `owned_anchored` | both copies came from their witnesses, and E or the anchoring event is not receipted to its log's threshold |
| `delegated` | `named_not_owned` or `refused` | M's log is a delegated identity's |
| `named_not_anchored` | `named_not_owned` | no interaction event of X seals E |
| `anchor_removed` | `named_not_owned` | a recovery rotation of X replaced the anchoring interaction, and nothing has anchored E since |
| `second_machine` | `named_not_owned` | X's log anchored a different Identity Agent first |
| `log_invalid` | `refused` | a log does not verify |
| `not_named` | `refused` | M's log does not name X in the owner set in force |
| `stale_copy` | `refused` | a copy does not carry on from another copy the verifier holds |
| `log_unchecked` | `refused` | a log needed for the answer was not supplied or cannot be judged |
| `duplicity` | `refused` | a log holds two validly signed events at one place that no recovery explains |

## The vector file

`seeds` are 32-byte Ed25519 seeds (RFC 8032) in lowercase hex, by a label;
every key that signs an event comes from one. `witnesses` gives each witness's
seed and the non-transferable identifier it makes. Each case has `machine` and
`owner` (and `other_logs`), each with `messages` (an event's JSON followed by
its attached signatures, as text), `receipts` by the SAID of the event
receipted, `source` (`its_witnesses` or `checked_party`) and `kept` (other
copies the verifier holds). `expect` gives `grade`, `reason`, the two
identifiers, `event` and `event_sn` (E, once step 2 has found it) and
`anchored_by` (the SAID of the anchoring interaction, for the owned grades).
