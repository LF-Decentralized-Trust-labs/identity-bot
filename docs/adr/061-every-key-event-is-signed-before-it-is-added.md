# ADR-061 — Every key event is signed before it is added, including where the app holds the key

**Status:** Accepted
**Date:** 2026-10-31
**Amends:** ADR-044 (the paragraphs on rotations appended unsigned and on keys held by the app, and the sentence that signing is never split into a prepare and a commit), ADR-022 (how post-quantum pre-rotation is committed and revealed)
**Relates to:** ADR-016 (Witness protocol), ADR-029 (Backing up without the recovery phrase), ADR-031 (Who witnesses what), ADR-037 (One KERI engine on every platform), ADR-039 (A backup is of an identity), ADR-049 (One signing form), ADR-060 (One accepted string per spelling)

## Context

This section describes the code as it is before this decision.

**Today every rotation is added to the key log unsigned.** `Engine.Rotate` and
`RotateToMultisig` append through `extendByRotation`, which checks no
signature, and the rotation route stores whatever signature the caller sent,
which in practice is none. The event can reach witnesses in that state. A
verifier that checks signatures refuses the log from that event on. This holds
for every caller: the owner of a core-held identity, the multi-owner ceremony,
a recovery that rotates for a client, and the break-glass root rotation, which
is refused whole for exactly this reason.

**An identity whose key the app holds can be founded and then nothing else.**
An app may keep the signing key, derived from the recovery phrase in its own
secure storage, while a core keeps the log: inside the app, beside it, or
elsewhere with the app as its front end. The core finds no key it can derive
(`identitySigningSeed` answers `errKeyElsewhere`), refuses a rotation with
`409 key_not_held_here` (`mayRotateHere`), and the engine refuses an
interaction it cannot have signed.

**The post-quantum commitment exists, for the core only.** Where the core holds
a root seed, founding writes `n = [classical digest, post-quantum digest]` with
`nt = "1"`, and each ordinary rotation renews it. The ML-DSA-65 key derives
from the core's root seed. For an identity whose key the app holds, that key
would be the core's, and revealing it alone meets the threshold: the core
could rotate the identity by itself. Today a recovery rotation and the
multi-owner ceremony drop the commitment altogether; section 6 changes that. Revealing the post-quantum key has
never been possible, because the CESR code table has no code for it.

**The app cannot check the core's messaging keys**, which founding anchors as an
`IA-HYBRID-1` keyset derived from the core's root seed. The app has no ML-DSA
or ML-KEM to recompute them, so a core holding a different seed can plant keys
of its own.

**The app cannot learn which key is in force on a hosted Identity Agent.** It
reads `GET /api/identity` and `GET /api/kel`, which are owner routes, and to
sign as the owner it must first know which key is in force.

KERI's own client and agent split puts the pieces in the same places: the
client holds the keys and signs, the agent accepts only events that arrive
signed. What is missing is a way to have an event built without it being added,
and a way to add it only with its signatures.

## Decision

### 1. Every key comes from the phrase, on a path both sides share

The app and the core derive every key from the 64-byte BIP39 seed by SLIP-0010
for Ed25519 (`DerivePairwiseSeed` in `backup/crypto.go`,
`KeyManager.slip10Ed25519` in `packages/agent_client/lib/crypto/keys.dart`).
The derivation is SLIP-0010 for the Ed25519 curve, every step hardened:

- the master key and chain code are the left and right 32 bytes of
  HMAC-SHA512, keyed with the ASCII string `ed25519 seed`, over the 64-byte
  BIP39 seed;
- each step to index *i* (below 2^31) is HMAC-SHA512, keyed with the parent
  chain code, over the byte `0x00`, the 32-byte parent key, and *i* + 2^31 as
  four bytes big-endian; the left 32 bytes are the child key and the right 32
  its chain code;
- the 32-byte child key at the end of the path is the child seed.

Each child seed is a hardened child, so holding one reveals nothing about its
parent or its siblings. `backup/identity-key-vectors.json` is the reference:
every path below, for one fixed phrase, with the keys it must give.

| What | Path | Used |
|---|---|---|
| Classical signing key *j* | `m/44'/0'/0'/0'/j'` | committed by the establishment event at position *j* − 1, revealed by the one at position *j* (key 0 founds the identity) |
| Post-quantum next key, generation *j* | `m/44'/0'/0'/7000001'/j'` | committed by the establishment event at position *j*; revealed, if ever, by the one at position *j* + 1 |
| Messaging keyset, generation *g* | `m/44'/0'/0'/7000002'/g'` | anchored at founding (*g* = 0); a later generation when messaging keys are replaced |

An establishment event's **position** is how many establishment events come
before it: founding is 0, the first rotation 1, and so on. Superseded
interactions do not change it. After a move to a new phrase (section 10),
positions count again from the rotation that made the move, which is position
0 of the new phrase. The establishment event at position *j* always
commits `n = [digest of classical key j+1, digest of post-quantum generation
j]`, whichever key it revealed, so both sides can say what any event commits
to from its position alone.

**Position is not the sequence number.** `s` is the event's sequence number in
the log: it counts every event, interactions included, never restarts, and is
the only number on the wire. Position is never written anywhere; it is how the
signer picks derivation indices. An example log:

| `s` | Event | Position | Reveals | Commits |
|---|---|---|---|---|
| 0 | founding | 0 | classical 0 | classical 1, post-quantum 0 |
| 1 | interaction | — | — | — |
| 2 | rotation | 1 | classical 1 | classical 2, post-quantum 1 |
| 3 | interaction | — | — | — |
| 4 | phrase move, step 1 | old 2, new 0 | old classical 2 | new classical 1, new post-quantum 0 |
| 5 | phrase move, step 2 | new 1 | new classical 1 | new classical 2, new post-quantum 1 |

The post-quantum path is the one the core already uses
(`postQuantumPreRotationAt`). The messaging path is new: the core used to
allocate a branch for messaging keys and record the number in a file, so a
restore without that file could not find them. New identities, whoever holds
their key, use the fixed branch. Section 8 covers identities founded earlier.

**The post-quantum digest is frozen.** A commitment opens only if the revealed
key is the exact text that was digested, so the preimage is fixed here and
never changes for a commitment once made:

- The ML-DSA-65 public key (FIPS 204, 1952 bytes) is generated from the 32-byte
  child seed by `circl`'s `mldsa65.NewKeyFromSeed`.
- It is encoded as CESR qb64 under code `2AAE`: one zero lead byte before the
  1952 bytes, 2608 characters in all (`iacrypto.MLDSA65VerkeyQB64`).
- The commitment is Blake3-256 over the UTF-8 bytes of that qb64 text, written
  as qb64 under code `E` (44 characters). `E` is CESR's code for a Blake3-256
  digest.

This is the digest KERI itself takes of a next key: keripy 1.3.6 computes the
same value (a `Diger` with code `Blake3_256` over the key's qb64 bytes; checked
while drafting), and the vectors below assert byte equality with keripy's
output for every key they hold.

`2AAE` is the code proposed for this key in the CESR specification; it is not
yet assigned. Until a code is assigned, the engine accepts no post-quantum key
in `k` at all, so nothing can put one on the wire that other verifiers cannot
read. Once one is assigned, the engine accepts that code everywhere, and
accepts a key encoded under `2AAE` exactly where it opens a commitment made
under `2AAE`, and nowhere else, so commitments already written stay openable
by this engine. Other implementations that know only the assigned code could
not read a `2AAE` key in `k`. So after assignment the identity's first rotation
reveals only its classical key and re-commits its post-quantum key under the
assigned code (section 6), and `2AAE` never appears on the wire.

`backup/identity-key-vectors.json` holds, for one fixed phrase: classical keys
0–2; post-quantum generations 0–2 with each public key's qb64 and its digest;
messaging generations 0–1 with each keyset's anchor. The core and the app are
both tested against it.

### 2. Nothing enters a key log unsigned, and every valid log is accepted

The engine has one way to add an event, and it checks signatures there for
every kind of event. The same checks are how it verifies any other identity's
log.

- **Founding:** the signatures satisfy `kt` over `k`, and the identifier is the
  event's own digest.
- **Rotation:** the signatures satisfy the new `kt` over `k`, and the entries of
  the prior `n` opened by keys that signed satisfy the prior `nt`. A rotation
  that reveals only some committed keys (a partial rotation) is valid when they
  meet the prior threshold. A rotation may also name keys the prior `n` did not
  commit to (an augmented rotation); their signatures count toward `kt` only.
- **Interaction:** the signatures satisfy the current `kt` over the current `k`.

**The prior commitment is always the last establishment event's.** A rotation
opens the `n` and `nt` of the most recent establishment event before it, never
those of an interaction it follows (an interaction has none).

**Verifying is not emitting.** As a verifier the engine accepts every log the
KERI specification allows, augmented rotations included, or it would not be
interoperable. What this Identity Agent's own signers emit is narrower:
section 5 never produces an augmented rotation. That narrowness lives in the
signer's checks, never in what the engine accepts.

**Signature codes.** Every controller signature is an indexed Ed25519
signature in one of three CESR forms, as keripy's indexing table defines them
(checked against keripy 1.3.6):

| Form | Code | Length | Carries |
|---|---|---|---|
| Both lists, same place | `A` | 88 characters | one index, used for `k` and the prior `n` |
| Both lists, different places | `2A` | 92 characters | an index into `k` and an ondex into the prior `n`, two characters each |
| Current list only | `B` (or `2B` for a large index) | 88 (92) characters | an index into `k`; opens nothing |

Revealing the post-quantum key alone (opening `n[1]` with
`k = [post-quantum key]`) is index 0, ondex 1, code `2A`; written as `A` it
would be checked against `n[0]` and fail. The post-quantum signature codes are
CESR's to assign (section 6). Test vectors for every form are in the engine's
conformance vectors and in `backup/identity-key-vectors.json`.

The engine, and every witness, check a rotation's signatures this way:

```
E      = the last establishment event before this rotation
opened = {}            # places in E.n opened by a valid signature
signed = {}            # places in k signed by a valid signature
for sig in signatures:
    index = index of sig;  P = k[index]       # refuse if outside k
    refuse unless sig verifies over the event bytes under P
    signed += {index}
    if sig carries an ondex (codes A, 2A; for A, ondex = index):
        D = Blake3-256 digest of P's qb64 text, as qb64 (section 1)
        refuse unless D == E.n[ondex]         # refuse if outside E.n
        opened += {ondex}
refuse unless kt is satisfied by signed
refuse unless E.nt is satisfied by opened
```

An interaction's signatures carry one index each:

```
K, KT  = k and kt of the last establishment event
signed = {}
for sig in signatures:
    index = index of sig     # code A or B (2A, 2B for a large index); any ondex is ignored
    P = K[index]             # refuse if outside K
    refuse unless sig verifies over the event bytes under P
    signed += {index}
refuse unless KT is satisfied by signed
```

Duplicate signatures for one place count once.

**What the parser refuses.** In a production build an event is refused if any
key in `k`, or any signature, uses a CESR code the engine does not know, or has
the wrong length for its code. Test builds add the test-only table described
below and nothing else. The digests in `n` are opaque until a rotation opens
them: the engine checks only that each is a well-formed digest, so a
commitment to a post-quantum key is valid in production long before that key
could be revealed.

**What a witness receipt attests to.** In KERI a receipt is the witness's own
signature over the event's digest (`d`); it does not cover the controller's
signatures. So a signer confirms what a witness saw by the digest it receipted,
and the dual-index signatures of section 2 need no change to receipts. What a
witness must do differently is verify those signatures before it receipts, as
it verifies any other (section 2's procedure).

`extendByRotation` is removed. A core that holds the key signs through the same
path with its installed signer, and the first thing it persists for any event
is the event with its full signatures: a crash between building and adding
leaves nothing. The event record keeps a list of indexed signatures.

**What the engine accepts never depends on the stage setting of section 6.**
The setting changes what the app and core emit. The engine accepts every
threshold a valid log may contain, including `nt = "1"` with two commitments,
with no deadline. Which key codes it accepts follows only from what the CESR
specification has assigned (section 1), and changes only with a release of the
engine. Tests exercise a post-quantum key in `k` with a test-only CESR table
that treats `2AAE` as assigned; that table is compiled into test builds and
never into a production one.

### 3. The core prepares an event; the signer commits it signed

Two owner routes, closed to controllers, because a key event writes the state
that decides who the owner is (ADR-044). On a core with no identity, a founding
prepare and commit pass the same founding gate as `/api/inception`, and a
founding is refused while an identity exists.

**`POST /api/events/prepare`** builds an event and returns its bytes. It adds
nothing to the log, keeps nothing, and sends the bytes to nobody but the caller.

```json
{
  "aid": "E…",                    // absent for a founding
  "t": "rot",                     // "icp" | "rot" | "ixn"
  "k": ["D…"], "kt": "1",         // founding and rotation
  "n": ["E…", "E…"], "nt": "1",
  "a": [],                        // anchors
  "owner_aid": "E…",              // founding only
  "owners": ["E…", "E…"],         // several owners: every owner's identifier
  "b": ["B…"], "bt": "2",         // founding: the witnesses
  "br": [], "ba": [], "bt": "2",  // rotation: witness changes and threshold
  "after": {"s": "4", "d": "E…"}  // rotation and interaction: the event this one follows
}
```

```json
{
  "raw_b64": "…",
  "hint": {"t": "rot", "i": "E…", "s": "5", "p": "E…", "d": "E…",
           "k": ["D…"], "kt": "1", "prior_n": ["E…", "E…"], "prior_nt": "1"}
}
```

`hint` is for display and diagnosis. Nothing signs on its strength: the signer
checks the bytes (section 5).

**`after`** names the event the new one follows, so `p` is that event's digest
and `s` is its sequence number plus one. A signer outside the core always
supplies it, from the key state it has verified itself (section 9), never
taking the core's tip on trust: a core that hid an establishment event would
otherwise get a competing one signed. Only the core's own internal path, for a
key it holds, defaults to its tip. For a
**recovery rotation** it may be the last establishment event, or any
interaction after it that is to be kept; the interactions after `after` up to
the tip are the ones the rotation supersedes. An `after` earlier than the last
establishment event, or a non-rotation with an `after` that is not the tip, is
refused (`409 tip_moved`, with the tip). A rotation whose keys cannot open the
`n` and `nt` of the last establishment event is refused here
(`422 not_committed`), whatever `after` names.

The founding request names its witnesses (`b`, `bt`): a set the app was
configured with, or one the person agreed to, which the core may propose
beforehand on its witness routes. The core composes no field of its own.

Prepare is a pure function of the request: KERI events carry no timestamp or
nonce, so preparing twice gives the same bytes.

**`POST /api/events/commit`** takes the event and its signatures:

```json
{ "raw_b64": "…", "sigs": ["AA…"] }
```

The core reads the event (refusing any value not in its one accepted spelling,
ADR-060), checks it belongs to this identity, and applies the section 2 rule
for its type:

- **`icp`:** only on a core with no identity (a founding is refused while one
  exists); signatures meet `kt` over `k`, and `i` is the event's digest.
- **`rot`:** `p` and `s` follow the tip or a valid recovery point; signatures
  meet the new `kt` and open the last establishment event's `n` to its `nt`.
- **`ixn`:** `p` and `s` follow the tip; signatures meet the current `kt` over
  the current `k`.

Then it adds the event, records the new key state, and starts sending it to
the witnesses through `witnessOwnLog`.

| Case | Answer |
|---|---|
| Added | `201 {"status": "recorded", "s", "d"}` |
| The same event is already at that place | `200 {"status": "already_recorded"}`; any further valid signature is kept |
| `p`/`s` follow neither the tip nor, for a rotation, a valid recovery point | `409 tip_moved`, with the tip |
| A different establishment event holds that place | `409 place_taken`, with its `s` and `d`; the refused event and its signatures are kept as evidence of duplicity |
| A signature does not verify, or a threshold is not met by a single-signer event | `400`; nothing is written |
| Thresholds partly met, for an event with several signers | `202 {"status": "waiting_for_signatures", "missing": …, "expires": …}` |

**`201` means added here and sent.** Receipts arrive asynchronously.
`GET /api/events/{s}/receipts` returns the receipts the core holds, as a
convenience. A signer outside the core does not take its word: it reads the
witnesses itself and verifies each receipt over the event's digest (section 4). A flow
that must not proceed until the event is established (anchoring a credential
on a rotation, say) waits until receipts meeting `bt` verify.

**Idempotency** is the event's digest: the same commit twice changes nothing.
**A replayed commit** is harmless, because the event authorises itself: it
carries its controller's signatures over its own bytes. **A stale prepare** is
caught at commit. **A commit that never comes** leaves the log as it was; what
remains is the signer's own record (section 4).

**Recovery rotation.** A rotation at `s` supersedes the interactions from `s`
to the tip when every event from the last establishment event onward is an
interaction, and `p` is the digest of the event at `s − 1` (the last
establishment event or a kept interaction). The core moves the superseded
interactions to a record of what was superseded, never deletes them, and sends
the witnesses the rotation. Witnesses apply it the same way (section 4). This
is how an owner whose current key was stolen undoes what the thief anchored,
and how the post-quantum reserve is used once a classical key is broken.

**Events with several signers** (an identity with several owners, a recovery
rotation for a client, the break-glass root rotation) use the same routes.
Each signer commits the same digest with its own signatures. The core holds
candidates by digest; more than one candidate may wait at a place, so one
signer cannot block another's proposal. A candidate is added when its own
signatures meet both the new `kt` and the prior `nt`. The other candidates at
that place are then dropped from the hold, and any that is a different
establishment event is kept, like a `place_taken` refusal, as evidence of
duplicity. Limits: at most 8 candidates per place and 32 per identity,
signatures per candidate no more than the keys that could sign it, and a
candidate expires after a configurable time (seven days by default, returned
in `expires`). Expiry drops the held candidate only. Nothing held ever reaches
a witness.

**Every other write path:**

- The founding, rotation and interaction routes stay for an identity whose key
  the core holds, and run prepare, the core's own signer, and commit
  internally. For a key held elsewhere they answer `409 key_not_held_here`,
  naming `/api/events/prepare` and `/api/events/commit`.
- The recovery rotation, the multi-owner ceremony and the break-glass root
  rotation run through prepare and commit, carry the post-quantum commitment
  (section 6), and add nothing until signed by the keys each event reveals.
  The break-glass root rotation stays refused until then.
- `POST /api/events/signature` attaches a signature to an event an earlier
  version added unsigned, and does nothing else. Those bytes are already in
  the log and may already be at witnesses, so signing them in place is the
  only migration; the fence is on both sides:
  - **the core:** at upgrade, every event then in the log without a signature
    is marked as such, once. The route accepts only a marked event, only a
    signature that verifies over its stored bytes and meets the section 2 rule
    for its type, never creates an event or changes a field, and refuses every
    event added after the upgrade;
  - **the signer:** before signing a stored event, the app runs the section 5
    checks over the stored bytes, exactly as for a prepared event. If they are
    not the event this phrase would have produced, with no extra digest, key or
    anchor, it does not sign, and the person is shown the event instead.

  The route is removed in the first release that no longer upgrades directly
  from a version that could add events unsigned.
- `POST /api/identity/restore` installs a log on a core with no identity only
  after verifying the whole chain: every digest, every indexed signature,
  every pre-rotation opening and every threshold. It installs no seed.

### 4. The signer reserves a place before it signs

ADR-044 rejected a prepare and a commit for a device that signs through its own
core, because two signed events at one place would be duplicity. That holds for
that path. Here the rule is kept where the signature is made.

The app's record (`TheEventsThisDeviceSigned`, replacing
`TheEventsThisDeviceAskedFor`), per identity and sequence number, holds the
event's bytes, digest and prior digest, its signatures once made, and its
state: `reserved`, `signed`, `recorded` or `dead`.

1. **Reserve before signing.** The app writes `(identity, s, p, d, bytes)` to
   secure storage atomically, then signs. It refuses to sign a second digest
   at a reserved place. A crash between reserving and signing leaves a
   reservation for those exact bytes, which may be signed later and nothing
   else.
2. **Then record the signature, then commit.**
3. **Finish before starting.** Before preparing anything, the app commits any
   `signed` event again, byte for byte.
4. **A recovery rotation may supersede a pending interaction.** When the person
   asks for a recovery rotation, a reserved or signed interaction at a place
   the rotation will take is marked `dead`. This is not duplicity: KERI lets a
   rotation supersede interactions.
5. **The app sees its event reach the witnesses itself.** After a commit,
   whatever the core answered, the app reads the identity's witnesses and
   verifies their receipts over the event's digest. Any signed event of its own that
   the witnesses do not hold within a short wait, it sends them itself
   (`POST /witness/event`, ADR-016), so a core that answers `201` and forwards
   nothing cannot pin the identity. A signed event the app holds is portable:
   it can go to the witnesses, or to a new core.
6. **`place_taken` is confirmed before anything is given up.** The app asks
   enough of the witnesses to meet `bt` what they hold at that place. Only if
   they hold a different establishment event is its own marked `dead`. If they
   do not, the core is withholding the event, and item 5 applies.
7. **`tip_moved` is retried with care.** The app reads the key state again
   (section 9), checks every event it has not seen as it would before signing,
   and prepares again with `after` taken from that key state, at most three times with increasing
   delay. A place that keeps moving under it means the phrase is live on
   another device; signing stops and the person is told (section 10).

**What first-seen settles.** Duplicity is exactly this: two establishment
events with different digests at the same `s` in one identity's log. Witnesses
keep the one they saw first, and the other is evidence of it. A copy that is
merely shorter than another (a witness that has not caught up) is not
duplicity.
A rotation supersedes interactions at its place even when the interactions
were seen first. Two signed establishment events at one place can therefore
exist only where the same phrase is live on two devices at once and both
rotate.

### 5. The signer signs only bytes it has parsed and checked itself

The core supplies the bytes, so the signer checks the bytes, not anything said
beside them:

1. It decodes `raw_b64` with the engine's own parser, reached through `keymath`
   (section 7), never a Dart CESR parser.
2. It checks `d` is the digest of those bytes, as the engine computes it, and
   that `i` is `d` at founding.
3. It compares every field, `v`, `t`, `i`, `s`, `p`, `d`, `k`, `kt`, `n`, `nt`,
   `a`, `b`, `bt`, `c`, `br`, `ba`, to the value it expects, and requires that
   the event has no other field.
4. It signs those same bytes, with the indices section 2 gives.

**The rule:** every field equals what this signer derived from its phrase, the
`after` it chose from its verified key state (section 9), and what the person
asked for. `p` is `after`'s digest and `s` its sequence number plus one. There
are no allowances for an extra digest or an extra anchor, so a core that holds
a different seed, or none, cannot add a key of its own, and no proof that the
core holds the phrase's seed is needed.

**"No other field" is this project's choice, not KERI's.** KERI does not
require a signer to refuse fields it did not expect; this signer does, because
a field it cannot judge is one it should not authorise. When a KERI version
adds a field an event may carry, the signer is updated deliberately to know
what that field should hold, and until then refuses events that carry it.

The cases, for an identity with one owner. *j* is the position of the event
being signed (section 1), and *P(x)* is the digest of key *x*.

- **Founding** (position 0): `k = [classical 0]`, `kt = "1"`,
  `n = [P(classical 1), P(post-quantum 0)]`, `nt = "1"`, `c = []`, `b` and `bt`
  as the founding request named, and anchors exactly `[owner seal]` (when an
  owner was asked for) followed by the messaging keyset of generation 0. Any
  configuration trait is refused, including establishment-only (`EO`),
  do-not-delegate (`DND`) and no-backers (`NB`).
- **Routine rotation** (position *j*): `k = [classical j]`, `kt = "1"`,
  `n = [P(classical j+1), P(post-quantum j)]`, `nt = "1"`; `br`, `ba`, `bt` and
  `a` exactly as asked. Signature index 0, prior index 0.
- **Post-quantum reserve reveal** (position *j*; only behind the stage setting,
  section 6): `k = [post-quantum j−1]`, `kt = "1"`,
  `n = [P(classical j+1), P(post-quantum j)]`, `nt = "1"`. Signature index 0,
  prior index 1. Classical key *j*, committed and never revealed, is skipped
  for good.
- **First stage-two rotation** (position *j*; behind the setting, and only
  after the re-commit rotation of section 6):
  `k = [classical j, post-quantum j−1]`, `kt = "2"`,
  `n = [P(classical j+1), P(post-quantum j)]`, `nt = "2"`. Signatures index 0
  prior 0, and index 1 prior 1. It opens both entries of the prior `n`, which
  meets the prior `nt = "1"`.
- **Later stage-two rotations:** the same shape; the prior `nt = "2"` is met
  only because both entries are opened.
- **Recovery rotation:** the fields of whichever rotation above applies at
  position *j*, with `p` and `s` from the `after` the signer chose (the last
  establishment event or a kept interaction). It opens the last establishment
  event's `n`.
- **Moving to a new phrase:** the two rotations section 10 writes out field by
  field. In step 1, `k` holds the old phrase's key and `n` the new phrase's
  digests; the signer derives both from the two phrases it holds at that
  moment.
- **Interaction:** exactly the anchors asked for. In stage two it is signed by
  both keys in force.

**For an event with several signers** (several owners, a recovery for a
client, the break-glass root rotation), each signer checks what is its own and
what was agreed, and the rest it cannot derive. The prepare request names every
owner's identifier (`owners`), and each signer keeps that list in its own
record from the ceremony, so it sorts the list and computes section 6's layout
itself before signing, rather than taking the layout from the core:

- its own current key is in `k` at the index it will sign with;
- its own next classical and post-quantum digests are in `n` at the places the
  fixed layout of section 6 gives it;
- the lengths of `k` and `n`, and `kt` and `nt`, are those the ceremony agreed;
- `a`, `b`, `bt`, `br`, `ba` and `c` are as agreed, and every other field
  follows the rule above.

Every signer checks the same bytes and signs the same digest.

An identity founded earlier, whose `n` names only the classical key, gains its
post-quantum commitment at its next rotation.

### 6. Post-quantum pre-rotation, in two stages

**Stage one, from this decision.** Every establishment event commits
`n = [classical next, post-quantum next]` with `nt = "1"`, both derived by
whoever holds the phrase. This includes the recovery rotation and the
break-glass root rotation. A routine rotation
reveals the classical key alone, which meets the threshold, and commits to a
fresh pair. The post-quantum key is a reserve: a rotation revealing it alone
also meets the threshold (index 0, prior index 1, section 2). That reveal needs
an assigned code, so in stage one it is built and tested, and is never
published.

**With several owners** the same `nt = "1"` over the whole `n` would let one
owner's post-quantum reserve meet the whole identity's threshold. So in the
multi-owner ceremony each owner supplies their own next classical and
post-quantum digests, and `kt` and `nt` stay the ceremony's own thresholds,
written so that an owner's two commitments count once, for that owner.

*The layout is fixed, so every signer can check it.* The owners are ordered by
their identifiers, compared as ASCII strings, ascending. Owner *i* (from 0)
then has:

- in stage one, `k[i]` = their current classical key, and `n[2i]`, `n[2i+1]` =
  their next classical and next post-quantum digests. They sign at index *i*,
  ondex *2i* (code `A` for owner 0, `2A` for the others);
- in stage two, `k[2i]`, `k[2i+1]` = their classical and post-quantum keys, with
  `n` laid out as in stage one, so index and ondex are equal (code `A`).

*The thresholds*, exactly as keripy 1.3.6 serialises them (generated with its
`Tholder` and checked against which signers satisfy them):

| Owners | Stage | `kt` | `nt` |
|---|---|---|---|
| two, both must act | one | `"2"` | `[["1", "1"], ["1", "1"]]` |
| two, both must act | two | `[["1/2", "1/2"], ["1/2", "1/2"]]` | `[["1/2", "1/2"], ["1/2", "1/2"]]` |
| three, any two | one | `"2"` | `[{"1/2": ["1", "1"]}, {"1/2": ["1", "1"]}, {"1/2": ["1", "1"]}]` |
| three, any two | two | `[{"1/2": ["1/2", "1/2"]}, {"1/2": ["1/2", "1/2"]}, {"1/2": ["1/2", "1/2"]}]` | the same as `kt` |

Each inner list belongs to one owner, in order. Where every owner must act,
one clause per owner is enough: each clause needs one of that owner's keys in
stage one, both in stage two. Where only some owners must act, each owner is a
nested clause (`{"weight": [...]}`) carrying that owner's weight and satisfied
by their own keys. Checked with keripy 1.3.6: in the three-owner stage-one
case, owner 0's two keys alone do not meet `nt`, and owner 0's classical key
with owner 2's post-quantum key do. The nested form needs a keripy recent
enough to read it (1.3.6 does; 1.1.17 refuses it), which is why the
every-owner case uses the plain form.

Stage one protects the next keys: they sit behind Blake3-256 digests, which a
quantum computer cannot invert. Two things it does not protect:

- **The key in force once revealed.** A quantum attacker can recover an Ed25519
  private key from the public key, and so sign interactions with it.
- **The rotation that reveals it.** The moment a rotation reveals classical key
  *j*, the same attacker can sign a second rotation at the same `s`, with the
  same `k` and a different `n` of its own. That is duplicity between two
  establishment events, settled only by which the witnesses saw first.

**Stage two** closes both. A rotation reveals both committed keys,
`k = [classical, post-quantum]` with `kt = "2"`, and commits
`n = [classical next, post-quantum next]` with `nt = "2"`. The first such
rotation is valid under stage one's `nt = "1"` (it opens both entries, which
also meets a threshold of one). From then on every event and every rotation
needs both signatures: the "both must verify" rule of ADR-022, enforced by the
identity's own thresholds rather than by our verifier.

Stage two starts only when the CESR specification assigns codes for an
ML-DSA-65 public key and for its indexed signatures (the proposals are CESR
pull request #165 and issue #171), and both are merged. Until then the full
stage-two path is built and tested behind one setting that is off. Turning it
on changes what is emitted, never what is accepted (section 2).

**The first rotation after assignment re-commits.** Once a release knows the
assigned codes, an identity's next rotation is a routine one: `k = [classical
j]`, opening `n[0]`, committing `n[1]` under the assigned code. Only once that
rotation is witnessed may a post-quantum key be revealed, by a reserve reveal
or a stage-two rotation. So the key that is revealed was committed under the
assigned code, and `2AAE` never appears in `k`.

**The rotate-in path, and who can follow it.** An identity is quantum ready
only if a post-quantum key can actually be rotated in once the codes exist.

- **Every implementation that knows the assigned code** can follow the path
  above: a classical re-commit, then a reveal of a key committed under that
  code. This is the path the design uses.
- **A commitment made under `2AAE`**, if CESR assigns a different code, can be
  opened by this engine and by no implementation that knows only the assigned
  code. The app opens one only in an emergency (Ed25519 broken before the
  re-commit rotation could be made), knowing that other implementations will
  refuse the log from that event on. If CESR assigns `2AAE` itself, those
  commitments open everywhere.

Three things are held fixed and tested so the path stays real: the digest
preimage (section 1), this engine's opening of commitments already written
under `2AAE` (section 1), and its acceptance of a rotation that opens `n[1]` and
of the first rotation revealing both keys (section 2).

`nt = "2"` is not used in stage one: every rotation would then have to reveal
the post-quantum key, which cannot be published, so no identity could rotate.

### 7. The app computes with the core's own code, compiled into the app

The app needs ML-DSA-65 key generation from a seed and signing, ML-KEM-768 key
generation from a seed (for the messaging keyset), and the engine's parser and
digest (section 5). The rule against hand-rolled cryptography rules out writing
any of them. The options:

- **A Dart package.** Several exist: pure-Dart ports and wrappers of C
  libraries, most new, each with one maintainer and no independent review. Each
  is a second implementation that must agree with the core's to the byte, the
  divergence ADR-037 removed a whole engine to end.
- **A C library through the app's FFI** (liboqs, or the ML-DSA implementation it
  uses). Better reviewed, though liboqs advises against production use. Still a
  second implementation, plus a C build for four platforms.
- **The core's HTTP API, handed the seed for a moment.** Rejected. The core may
  be elsewhere, and handing a machine somebody else operates the seed gives the
  identity away (ADR-029). A local core is still a long-running process with a
  listening port and storage of its own.
- **The core's own Go code, compiled into the app.** Chosen. A small Go
  package, `keymath`, wraps what the core already uses: `circl` ML-DSA-65 and
  ML-KEM-768, the CESR encoding and Blake3 digests in `iacrypto`, and the
  engine's event parser. It imports no network or storage package. It takes a
  32-byte child seed, never the root, and returns a public key, digest,
  signature, anchor, or a parsed and digest-checked event. On iOS and Android
  it is exported by the core library linked into the app, and runs in the
  app's process. On macOS and Windows the app runs the bundled core binary as a
  one-shot `keymath` command: the request goes in on standard input, the answer
  comes out on standard output, and the process exits. No port opens and
  nothing is written to disk.

**It is still app-held.** A key is app-held when its seed stays in the app's
custody: in its secure storage at rest, and only in memory the app controls
while in use, never on a network and never in a process that outlives the
call. Standard input to a child process is an anonymous pipe that only the two
processes can read, unlike a command-line argument, which any process can.

**The binary is checked before it is run.** On macOS the app checks that the
`keymath` binary carries a valid code signature by the same signer as the app;
on Windows, a valid Authenticode signature by the same signer; and on both, a
hash recorded at build time. If a check fails the app does not run it and
reports an error; there is no fallback. On iOS and Android `keymath` is linked
into the app's own signed binary.

**Seeds are held as briefly as the platform allows.** The app zeroes every
buffer holding a seed or child seed after use, and `keymath` zeroes its copies.
Go's garbage collector may have copied a buffer before it is zeroed, and Dart's
may too, so zeroing is a reduction, not a guarantee. The one-shot command ends
with its process, which releases everything it held. Memory locking is used
only where a platform supports it without native code of our own; it is not
claimed elsewhere. Seeds, child seeds, signatures and `keymath`'s input are
never logged, written to a crash report, or echoed in an error.

There is one implementation of each algorithm, so the app and the core agree
by construction, and the shared vectors prove it on each platform. `keymath`
replaces `cmd/mldsa-cli`, which takes its seed on the command line.

### 8. The app chooses the messaging keys; the core holds them

The core receives messages for the identity while the app is closed, so it
holds the messaging keys' private halves. The app chooses them:

1. It derives the messaging seed for generation *g* and computes the keyset's
   anchor with `keymath`.
2. It hands the core that seed on `POST /api/keystore/messaging-seed`, an owner
   route closed to controllers. The core derives the keyset, stores the seed
   with the protection it gives a root seed, and returns the anchor it derived;
   the app compares the two.
3. It prepares the founding (or, for a later generation, an interaction)
   anchoring exactly that keyset, checks it (section 5) and commits it.

At commit the core refuses an anchor of a keyset it does not hold. The
messaging seed is a hardened child: it lets the core read and sign messages for
the identity, which is its job, and gives it no part of the signing or
pre-rotation keys.

**Identities founded before the fixed branch** keep the keyset their founding
anchored, at the branch their record names, until it is replaced. The app
replaces it with an interaction anchoring generation 0 of the fixed branch,
after handing the core that seed; the latest anchored keyset is the one the
identity is reached on. Until that interaction is witnessed the earlier keys
stay live. For an app-held identity whose earlier keyset came from a core's own
seed, this is the step that takes those keys out of use.

### 9. The signer learns the key in force without asking an owner route

The app keeps its identity's identifier in its own storage, from founding or
recovery; it is public. It has three sources for the key in force, in order:

1. **Its own record** (section 4). Only a holder of this phrase can add an
   establishment event, so the highest establishment the app recorded is the
   key in force unless the phrase has been used elsewhere.
2. **The identity's witnesses' copies of the log** (ADR-031), from enough of
   them to meet `bt`, read on their public routes.
3. **The Identity Agent's discovery record** at its public address.

Every copy from sources 2 and 3 is checked by the app's local core on
`POST /public/key-state`, a public route that reads a key log, verifies it as
section 2 does, and returns the key state it establishes: the last
establishment event, `k`, `kt`, `n`, `nt`, and the anchored messaging keysets.
It computes over what it is sent, fetches and stores nothing, and has the rate
limits of `/public/login/key`.

**How copies are combined.**

- **Duplicity:** two verified copies hold establishment events with different
  digests at the same `s`. Signing stops and the person is shown both.
- **A prefix is consistent.** A copy that stops earlier than another, and
  agrees with it as far as it goes, is a copy that has not caught up.
- **Quorum:** among copies with no duplicity between them, the app takes the
  longest chain of establishment events that copies from enough witnesses to
  meet `bt` hold, then the longest run of interactions after it.

An establishment event the app did not sign and does not recognise also stops
signing until the person has looked at it. The key state that results is what
the app takes `after` from.

The app reads the witnesses when its own record cannot answer: on first use,
after recovery, after a commit whose outcome it has to confirm, and when an
Identity Agent refuses a signature as stale. It does not read them before every
signature.

An owner signature names the establishment event it was made under, by
sequence number and digest, as KERI's signatures by a transferable identifier
do. An Identity Agent refuses one made under an earlier establishment with
`401 stale_key_state`, which tells the signer nothing beyond what it claimed;
the app reads the key state again. That also settles a rotation whose commit
answer was lost: the app reads, it does not guess.

Where the core is local, it both keeps the log and checks copies of it. That is
not circular in a way that matters: it runs in the app's process or under the
same user, and source 1 is what guards against a core adding events of its own.

### 10. Recovering from the phrase, and leaving a phrase behind

**Recovery onto a new device** needs the phrase and one public locator: the
identifier, a backup archive (ADR-029, ADR-039), or the address of an Identity
Agent that keeps the log. The identifier depends on the witnesses the core
chose at founding, so the phrase alone does not determine it.

1. The app reads the log from enough witnesses to meet `bt` and, where given,
   from the Identity Agent, has its local core verify each copy, and combines
   them as section 9 does: duplicity (different establishment digests at one
   `s`) stops recovery and shows the person both; otherwise it takes the
   longest establishment chain a `bt` quorum holds, then the longest run of
   interactions after it.
2. It checks every establishment event from the last phrase move onward names
   this phrase's keys at consecutive indices and commits to this phrase's next
   keys, and finds the key in force *j* and the messaging generation *g* by
   matching what it derives.
3. It installs the log in its new core (`POST /api/identity/restore`, which
   verifies the whole chain) and hands that core the messaging seed for *g*.
4. Its record starts from the log's tip.

**The phrase is the root of every key.** Every future key derives from it, so
rotating protects against losing one key, not the phrase or a device holding
its seed. A second device that still holds the phrase is not shut out by any
rotation. Where the phrase or such a device may be in somebody else's hands,
the person moves the identity to a **new phrase**, in two rotations:

1. At old-phrase position *j*: `k = [old phrase's classical key j]` (opening
   the prior `n[0]`), `kt = "1"`, `n = [digest of new phrase classical key 1,
   digest of new phrase post-quantum generation 0]`, `nt = "1"`. This is
   position 0 of the new phrase. The new phrase's key does not appear in `k`;
   it was never committed to.
2. At new-phrase position 1: `k = [new phrase classical key 1]` (opening
   `n[0]` of step 1), `kt = "1"`, `n = [digest of new phrase classical key 2,
   digest of new phrase post-quantum generation 1]`, `nt = "1"`.

Between the two, the old phrase's key is still the key in force: a holder of
the old seed can sign interactions, and cannot rotate, since it does not hold
the new `n`. Step 2 is made as a recovery rotation that supersedes any such
interactions. Until step 1 is witnessed, a holder of the old seed can race it
with a competing rotation, and first-seen between establishment events decides;
doing step 1 at once is the defence. Key-in-force reading accepts establishment
events before a move that name keys of another phrase, provided the chain from
the move onward is this phrase's.

### 11. Platforms

The capability applies to every platform where an app holds an identity's key:
macOS, Windows, iOS and Android. All four get the code in the same change. The
core work is shared Go. `keymath` reaches the app in two forms over one Go
package: linked into the app on iOS and Android, the checked one-shot command
on macOS and Windows. The shared vectors and the end-to-end flow are run on
each platform before it is called working there; one the change cannot yet be
run on is reported as untested there, with what would prove it.

### 12. What other KERI implementations see

The key events are standard KERI. That is a claim the build proves rather than
assumes: stock keripy validates a full test log of every event shape this
design produces, from founding onward, and keriox validates the shapes the
engine's existing harness already gives it. Each statement below about other
implementations holds to the extent those checks pass; the build fails if they
do not.

- **Standard, and checked against keripy:** founding with two next-key
  commitments; routine rotation; partial rotation; recovery rotation
  superseding interactions, both from the last establishment event and from a
  kept interaction; multi-owner rotation with the thresholds of section 6;
  the two rotations of a phrase move; interactions; indexed controller
  signatures in the `A`, `2A` and `B` forms; witness receipts.
- **Where dual-index signatures appear on the wire:** in multi-owner rotations
  (every owner after the first) and, once codes are assigned, in a
  post-quantum reserve reveal. A single-owner routine rotation uses `A`.
- **Not checked against keriox, a stated limitation:** the nested thresholds
  of section 6. Nothing here claims keriox reads them; they are checked there
  once keriox supports them.
- **Thresholds that need a recent keripy:** the nested form used when only
  some owners must act. keripy 1.3.6 reads it; 1.1.17 does not.
- **This Identity Agent's own API, not protocol:** `/api/events/prepare`,
  `/api/events/commit`, `/api/events/{s}/receipts`,
  `/api/keystore/messaging-seed`, `/api/identity/restore` and
  `/public/key-state`. Another implementation never needs them to verify
  anything; they are how this software builds and stores events.
- **This project's own conventions, carried inside standard fields:**
  - the `IA-HYBRID-1` messaging keyset anchor (`{"ia", "ka", "sa"}`) is not one
    of KERI's defined seal types. To any other implementation it is ordinary
    data in an event's anchor list, covered by the event's digest and
    signatures like anything else there;
  - the derivation paths and positions of section 1 decide which keys are used,
    and nobody else needs to know them;
  - the owner signature that names its establishment event is this project's
    request-signing form (ADR-049), not a KERI message;
  - how events travel to witnesses (ADR-016) is this project's; the events and
    the receipts are KERI's.
- **Not on the wire until CESR assigns it:** no post-quantum key or signature
  code appears in any published event. `2AAE` exists only inside the text a
  next-key digest was taken over, and a digest does not reveal it. After
  assignment the re-commit rotation of section 6 keeps it off the wire for
  good, except in the emergency section 6 names.
- **Narrower in what it emits, never in what it accepts:** this Identity
  Agent's signers never produce an augmented rotation (a key in `k` the prior
  `n` did not commit to). As a verifier the engine accepts one wherever KERI
  does (section 2).
- **Local records, never sent:** the record of superseded interactions, the
  duplicity evidence kept from `place_taken` and dropped candidates, and the
  app's record of what it reserved and signed.

## Consequences

- No event enters a key log, or reaches a witness, without the signatures its
  keys require. That covers founding, rotation, interaction, the recovery
  rotation, the multi-owner ceremony and the break-glass root rotation.
- An identity whose key the app holds can found, rotate, interact, anchor
  credentials, recover, and move to a new phrase.
- The core holds no key it could use to rotate an identity whose key the app
  holds; its post-quantum commitment and messaging keys are the app's.
- A hosted Identity Agent can be driven by an app that holds the key with no
  owner route needed to learn which key to sign with, and cannot pin the
  identity by withholding a signed event.
- Phrase-only recovery needs one public locator.
- The next keys are protected against a quantum attacker from founding. The key
  in force, and the rotation that reveals it, wait for the CESR code assignment;
  the switch is one setting.
- Events grow once stage two reveals ML-DSA-65 keys and signatures (about 2.6 KB
  and 4.4 KB as text), as ADR-022 accepts.
- The app keeps a record of what it reserved and signed and depends on it.
  Losing it (a wiped device) loses nothing the witnesses do not also hold.

## Alternatives considered

- **Keep appending first and signing after, and repair stranded events.** The
  event exists, and may be witnessed, before anybody has authorised it.
- **Have the app build events itself**, as KERI's client and agent split does.
  It would mean CESR serialisation and digests written in Dart. The core
  building and the app parsing with the same engine gives the same assurance.
- **Require both commitments now (`nt = "2"`).** No identity could rotate until
  the post-quantum code exists.
- **Publish the post-quantum key now under the proposed code.** It would
  protect the key in force today, and a key log can never be changed: if the
  code is assigned differently, every log that revealed it is unreadable by
  other implementations for good.
- **Keep the core's post-quantum key and prove the core holds the phrase's
  seed.** It leaves a key the app cannot recompute in its identity.
- **Each of the other key-math options** in section 7.

## What this does not decide

- **What a credential anchor must say.** The content checks before anchoring a
  credential stay those of ADR-045; the anchoring interaction uses these
  routes.
- **The device that signs through its own core.** ADR-044's signing queue is
  unchanged.
- **Making the identifier recoverable from the phrase alone**, for example by a
  phrase-derived locator held by witnesses. That changes the witness protocol,
  and can be added later for existing identities as well as new ones.
