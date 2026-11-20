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

Both are KERI's event seal: an object with exactly the three fields `i`, `s`
and `d`.

```
{"i": <identifier>, "s": <sequence number>, "d": <the event's SAID>}
```

A writer writes them in that order. A reader takes them in any order, because
the order of an object's fields is the writer's business and changes nothing
the seal says. `i` and `d` are strings that are not empty. `s` is a string, the
sequence number in lowercase hexadecimal with no leading zero: `"0"`, `"a"`,
`"1f"`. `"00"`, `"0x0"`, `"0A"`, `""` and a JSON number are not sequence
numbers.

- **The owner seal** (ADR-032) is an event seal in the `a` field of an
  **establishment event** of M that names an inception: `"s"` is `"0"` and
  `"d"` equals `"i"`. It says M names that identifier as an owner. In an
  establishment event an object that does not have exactly the three fields is
  not an owner seal and is passed over, as is one whose `s` is not `"0"` or
  whose `d` is not its `i`. One with exactly the three fields and an `i` or `d`
  that is empty or not a string cannot be read: in M's log it makes the log
  `log_invalid`, and in a log looked up in step 7 it makes the answer
  `log_unchecked`.
- **The anchor** is an event seal in the `a` field of an **interaction event**
  of X that names an establishment event **E** of M: `{"i": M, "s": E's
  sequence number, "d": E's SAID}`. For the owner named at founding E is M's
  inception and the seal is `{"i": M, "s": "0", "d": M}`. An event seal in an
  establishment event of X is never an anchor: it is X's own owner seal.

**Reading an interaction's `a`.** It is read element by element, and one
element never changes how another is read. Each element is one of three things:

- an **event seal**, as above;
- **another seal**: an object that lacks at least one of `i`, `s` and `d` (a
  digest seal `{"d": …}`, for example). It is shown not to be an event seal and
  is passed over;
- **unreadable**: anything that is not an object (a string, a number, a list,
  `null`), an object that has `i`, `s` and `d` and a further field, or one
  whose `i`, `s` or `d` is not as an event seal writes it. An `a` that is
  present and is not a list is one unreadable element.

An unreadable element is never passed over where step 6 reads: it may be an
earlier anchor.

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

A log of more than 2048 events is not judged: the answer is `log_unchecked`,
for either log, for another copy the verifier holds and for a log of another
identifier.

**What an owner identity's log may hold.** The check depends on this rule: an
owner identity's log carries no event seal other than anchors before its first
anchor, and nothing unreadable. Every event seal before the anchor has to be
looked up in the log it names (step 7). A seal there that names something with
no key log, such as a registry or a credential event, can never be looked up,
and leaves the answer `log_unchecked` for good. An owner identity is minted to
own one Identity Agent and is used for nothing else.

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
   to. Otherwise `log_invalid`. An identifier that is not the digest of its
   own inception (one that is a key, for example) is `log_invalid` too, however
   well its log is signed: no event seal can name its inception by it. The log
   carries on from every other copy held, or `stale_copy`.

   **X** is the `i` of the first event of the owner's log as it is written,
   which step 4 then verifies; a first event with none is `log_invalid`. **If X
   equals M the answer is `same_identifier`**: owned is proved from two logs,
   never one.

   M's log holds no delegated inception (`dip`), no delegated rotation (`drt`)
   and no event naming a delegator. Otherwise `delegated`: graded named, not
   owned when the owner set in force at M's latest establishment event names X,
   and refused when it does not. In practice this is a log that begins with a
   `dip`. A log that begins with an `icp` and holds a `drt` never reaches this
   test: a log rotates the way it was founded, so it does not verify and is
   `log_invalid`. The same goes for a `rot` in a log that begins with a `dip`.
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
   exactly**: identifier, sequence number and digest all equal. X's interaction
   events are read in order, and each one's `a` element by element, until that
   seal is found; nothing after it is read. An unreadable element met on the
   way is `log_unchecked`, whether or not a seal of E follows it. Where the
   log is read to its end and no seal of E is found: `anchor_removed` if an
   interaction event retired from X's log (see above) sealed E exactly, and
   `named_not_anchored` otherwise. (In a retired event an unreadable element
   is passed over: the event no longer stands.)
7. *(Step 6 of the record.)* **The anchor is the first anchor in X's log, or
   names the same Identity Agent as the first.** An anchor, for this count, is
   an event seal in an interaction event of X whose sealed event is an
   establishment event that carries an owner seal naming X. Each event seal
   read before the anchor in step 6, in order, is looked up in the log of the
   identifier it names. M's log and X's log are the copies being checked; a
   copy of either among the other logs is ignored. A seal names an event of a
   log when that log holds, at the seal's sequence number, an event with the
   seal's digest.
   - It names M, or X itself, and is not an event of that log, or is one and
     is not an anchor: passed over. No other log is needed for these.
   - It names M and is an anchor: the first anchor names M, and the step
     passes.
   - It names X itself and is an anchor (X names itself as an owner):
     `second_machine`.
   - It names another identifier whose log was not supplied, does not verify,
     is proven duplicitous, or does not hold the sealed event: `log_unchecked`,
     and the result names that identifier in `needs`.
   - Its sealed event is an establishment event whose owner seals cannot be
     read: `log_unchecked`, in whichever log.
   - It names another identifier and is an anchor: `second_machine`.
   - It names another identifier and is not an anchor (a delegation approval,
     for example): passed over.
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
| `log_invalid` | `refused` | a log does not verify, or its identifier is not the digest of its inception |
| `same_identifier` | `refused` | one identifier was given as both the Identity Agent and its owner |
| `not_named` | `refused` | M's log does not name X in the owner set in force |
| `stale_copy` | `refused` | a copy does not carry on from another copy the verifier holds |
| `log_unchecked` | `refused` | something at or before the anchor cannot be read, a log needed for the answer was not supplied or cannot be judged, or a log is too long to judge |
| `duplicity` | `refused` | a log holds two validly signed events at one place that no recovery explains |

## The vector file

`seeds` are 32-byte Ed25519 seeds (RFC 8032) in lowercase hex, by a label;
every key that signs an event comes from one. `witnesses` gives each witness's
seed and the non-transferable identifier it makes. Each case has `machine` and
`owner` (and `other_logs`), each with `messages` (an event's JSON followed by
its attached signatures, as text), `receipts` by the SAID of the event
receipted, `source` (`its_witnesses` or `checked_party`) and `kept` (other
copies the verifier holds). `expect` gives `grade` and `reason`, and, each
only when it is known: `machine` and `owner` (the two identifiers), `event` and
`event_sn` (E's SAID and its sequence number as a number, once step 2 has found
it; absent before, so an absent `event_sn` is not event 0), `anchored_by` (the
SAID of the anchoring interaction, for the owned grades) and `needs` (the
identifier whose log must be supplied, with `log_unchecked` from step 7).
