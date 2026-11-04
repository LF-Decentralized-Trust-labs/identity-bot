import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;

import '../crypto/keys.dart';
import 'key_math.dart';
import 'the_event_this_device_expects.dart';
import 'the_events_this_device_signed.dart';
import 'the_identity_this_device_holds.dart';
import 'the_witnesses_of_this_devices_events.dart';

/// The core answered a key-event request with a refusal.
class KeyEventRefused implements Exception {
  KeyEventRefused(this.what, this.statusCode, this.code, this.body);
  final String what;
  final int statusCode;

  /// The refusal's code: `tip_moved`, `place_taken`, `not_committed`,
  /// `unsigned_history`, `not_authorised`, `key_not_held_here` and the like.
  final String code;
  final String body;
  @override
  String toString() => '$what was refused ($statusCode $code): $body';
}

/// The core refused, for good, an event this device signed. The event still
/// holds its place, so nothing else is signed there: show the person [refusal]
/// and let them decide, through [TheKeyEventsThisDeviceMakes.letGoOf].
class AnEventWasRefused implements Exception {
  AnEventWasRefused(this.reservation, this.refusal);
  final Reservation reservation;
  final KeyEventRefused refusal;
  @override
  String toString() => 'the event at sequence number ${reservation.sn} of '
      '${reservation.aid} was refused: $refusal';
}

/// The core said another event holds the place of one this device signed, and
/// the witnesses confirm it: enough of them hold, at that place, a different
/// event in a log that verifies. Only a device holding this phrase can sign
/// one, so the phrase is in use elsewhere. This device's event is let go.
class ThePlaceIsTaken implements Exception {
  ThePlaceIsTaken(this.aid, this.sn, this.held);
  final String aid;
  final int sn;

  /// The digests the witnesses hold at that place, by witness.
  final Map<String, String> held;
  @override
  String toString() => 'another event holds sequence number $sn of $aid at '
      'its witnesses, so this phrase is in use on another device';
}

/// The core said another event holds the place of one this device signed, or
/// that the log moved past it, and the witnesses do not confirm it: the core
/// is withholding the event. It has been sent to the witnesses directly
/// ([witnessed] says what they answered); it is kept, so it can go to them
/// again, or to another core.
class TheCoreWithholdsThisEvent implements Exception {
  TheCoreWithholdsThisEvent(this.reservation, this.refusal, this.witnessed);
  final Reservation reservation;
  final KeyEventRefused refusal;
  final Witnessed witnessed;
  @override
  String toString() => 'the core refused the event at sequence number '
      '${reservation.sn} of ${reservation.aid} (${refusal.code}), and its '
      'witnesses do not hold another there';
}

/// The log kept moving: each time this device read where it ends and
/// prepared after it, another event had taken the place, or another device
/// rotated the keys. A phrase in use on another device does that; signing
/// stops and the person is told.
class TheLogKeepsMoving implements Exception {
  TheLogKeepsMoving(this.aid, this.tries, {this.rotatedElsewhere = false});
  final String aid;
  final int tries;

  /// Whether the keys in force changed: a rotation this device did not make.
  final bool rotatedElsewhere;
  @override
  String toString() => rotatedElsewhere
      ? 'the keys of $aid were rotated by another device; this phrase is in '
          'use elsewhere'
      : 'the log of $aid moved under this device $tries times; this phrase '
          'may be in use on another device';
}

/// What letting go of a refused event found.
enum LetGo {
  /// Enough witnesses answered and none holds the event: it was let go, and
  /// its place may be signed for again.
  released,

  /// A witness holds the event, in a log that verifies: it is in the
  /// identity's log after all, and is kept as committed.
  itIsInTheLog,
}

/// An identity's key state as this device has verified it: where the log
/// ends, which generation of this phrase's keys is in force, the witnesses in
/// force, and the keys the newest establishment event names in `k` (the
/// classical key alone at stage one, with the post-quantum key at stage two).
typedef KeyStateNow = ({
  Place tip,
  int generation,
  WitnessSet witnesses,
  List<String> keys
});

/// The seed of the post-quantum key in force for the phrase whose BIP-39 seed
/// is [seed], at [generation] with [keys] in `k`, checked to be the one this
/// phrase derives; null at stage one (`k` holds the classical key alone). At
/// stage two `k` holds the classical key of [generation] and the post-quantum
/// key of generation [generation] - 1, and nothing else is a stage this phrase
/// signs for ([ThePostQuantumKeyInForceIsNotThisPhrases]).
///
/// The one place this stage check is made, for the events this device makes and
/// the owner's requests alike. The seed handed back is the caller's to zero;
/// one that fails the check is zeroed here. [derive] is how the seed is
/// derived, given for a test to hold the buffer and see it zeroed.
Future<Uint8List?> thePostQuantumSeedInForce(
    KeyMath km, Uint8List seed, String aid, int generation, List<String> keys,
    {Uint8List Function(Uint8List seed, int generation)? derive}) async {
  if (keys.length <= 1) return null;
  if (keys.length != 2 || generation < 1) {
    throw ThePostQuantumKeyInForceIsNotThisPhrases(
        aid,
        'k holds ${keys.length} keys at generation $generation, and '
        'only two (the classical key and the post-quantum key of the '
        'generation before it) are a stage this phrase signs for');
  }
  final pq = (derive ??
      (s, g) => KeyManager.slip10Ed25519(s, KeyPaths.postQuantum(g)))(
    seed,
    generation - 1,
  );
  // Zeroed unless it is handed over, whether the check throws or fails.
  var handedOver = false;
  try {
    if ((await km.postQuantumNext(pq)).verkey != keys[1]) {
      throw ThePostQuantumKeyInForceIsNotThisPhrases(
          aid,
          'the post-quantum key in k is not the one of generation '
          '${generation - 1} this phrase derives');
    }
    handedOver = true;
    return pq;
  } finally {
    if (!handedOver) pq.fillRange(0, pq.length, 0);
  }
}

/// The keys in force are not a stage this phrase's keys can sign for: `k` is
/// neither the classical key alone, nor the classical key and the
/// post-quantum key of the generation before it. Nothing is signed.
class ThePostQuantumKeyInForceIsNotThisPhrases implements Exception {
  ThePostQuantumKeyInForceIsNotThisPhrases(this.aid, this.why);
  final String aid;
  final String why;
  @override
  String toString() => 'the keys in force for $aid are not ones this phrase '
      'signs for: $why';
}

/// An event this device committed: its identifier, place and digest, and
/// whether the core added it or holds it for further signers.
class Committed {
  Committed(this.aid, this.sn, this.digest, this.status, this.bytesB64,
      this.signatures,
      {this.witnessed});
  final String aid;
  final int sn;
  final String digest;

  /// `recorded`, or `already_recorded` when the core had it already. A core
  /// that answers `waiting_for_signatures` (202) has not recorded it: it holds
  /// the event for more signers than it was given, as it does for an owner at
  /// stage two whose event carries one key's signature. That is a
  /// [TheCoreWithholdsThisEvent] or an [AnEventWasRefused], never a [Committed].
  final String status;
  final String bytesB64;
  final List<String> signatures;

  /// What the witnesses answered, each receipt checked by this app; null when
  /// this device was given no witnesses to ask.
  final Witnessed? witnessed;
}

/// The paths of the keys this device derives from the phrase's seed, by
/// SLIP-0010, all hardened (ADR-061 sections 6 and 7).
class KeyPaths {
  static const _h = 0x80000000;

  /// The post-quantum next key of generation [g]: m/44'/0'/0'/7000001'/g'.
  static List<int> postQuantum(int g) =>
      [_h + 44, _h, _h, _h + 7000001, _h + g];

  /// The messaging keyset of generation [g]: m/44'/0'/0'/7000002'/g'.
  static List<int> messaging(int g) => [_h + 44, _h, _h, _h + 7000002, _h + g];

  /// The messaging keyset of a branch the Identity Agent allocated for it
  /// before 2026-10-31: m/44'/0'/0'/[branch]'/0'. Only to recognise a founding
  /// made then; a new one uses [messaging].
  static List<int> messagingOnAllocatedBranch(int branch) =>
      [_h + 44, _h, _h, _h + branch, _h];
}

/// How this device makes a key event of an identity whose keys it holds:
/// prepare, check, reserve, sign, commit (ADR-061 section 5).
///
/// The core prepares the bytes and adds nothing; this device checks them,
/// field by field, against the event it worked out from its own phrase
/// ([ExpectedEvent]); reserves the place ([TheEventsThisDeviceSigned]) so no
/// second event can be signed there; signs; records the signature; and
/// commits. An answer lost after signing leaves the reservation, which is
/// committed again before anything new ([finishSigned]). Nothing here asks the
/// core for a signature, or lets it choose a key.
///
/// After a commit, whatever the core answered, the event is sent to the
/// identity's witnesses and their receipts are checked here
/// ([TheWitnessesOfThisDevicesEvents]); the event is kept until enough have
/// receipted it. A `place_taken` is believed only when the witnesses confirm
/// it. A `tip_moved` before signing is prepared again after the key state
/// [readTheKeyState] reads, at most [retryDelays].length times. A refusal for good
/// is kept and shown, and only the person lets the event go ([letGoOf]).
class TheKeyEventsThisDeviceMakes {
  TheKeyEventsThisDeviceMakes(this._client, this._baseUrl, this._km,
      {TheEventsThisDeviceSigned? signed,
      TheWitnessesOfThisDevicesEvents? witnesses,
      TheIdentityThisDeviceHolds? held,
      this.readTheKeyState,
      this.readTheKeysInForce,
      this.retryDelays = const [
        Duration(seconds: 1),
        Duration(seconds: 2),
        Duration(seconds: 4)
      ]})
      : _signed = signed ?? TheEventsThisDeviceSigned(),
        _witnesses = witnesses,
        _held = held;

  final http.Client _client;
  final String _baseUrl;
  final KeyMath _km;
  final TheEventsThisDeviceSigned _signed;
  final TheWitnessesOfThisDevicesEvents? _witnesses;

  /// This device's own record of its identity (ADR-061 section 9): the
  /// identifier and witness addresses at founding, and each event once its
  /// core holds it. Null leaves no record.
  final TheIdentityThisDeviceHolds? _held;

  /// Reads an identity's key state again, as this device verifies it (ADR-061
  /// section 9): from copies of the log, every event this device has not seen
  /// checked as it would be before signing, never from the core's say-so.
  /// Null means a `tip_moved` is not retried.
  final Future<KeyStateNow> Function(String aid)? readTheKeyState;

  /// Reads the keys the newest establishment event names in `k`, as this
  /// device verifies them, for an identity this device's record cannot answer
  /// for (one founded before the record kept them): the stage is read from
  /// this, not given. Where null, [readTheKeyState] is asked. It answers with
  /// the generation as well as the keys, so a caller whose generation is out of
  /// date is told so on either path ([TheLogKeepsMoving]).
  final Future<KeyStateNow> Function(String aid)? readTheKeysInForce;

  /// The waits before each retry of a `tip_moved`.
  final List<Duration> retryDelays;

  /// Founds an identity on the keys [seed] (the phrase's BIP-39 seed) derives:
  /// the generation 0 signing key, committing to the generation 1 key and the
  /// generation 0 post-quantum key, and anchoring the generation 0 messaging
  /// keyset, whose seed the core is handed first so it can hold those keys.
  Future<Committed> found(Uint8List seed,
      {List<String> witnesses = const [], int toad = 0}) async {
    final key = KeyManager.publicKeyAt(seed, 0);
    final next = KeyManager.publicKeyAt(seed, 1);
    final pqSeed = KeyManager.slip10Ed25519(seed, KeyPaths.postQuantum(0));
    final messagingSeed = KeyManager.slip10Ed25519(seed, KeyPaths.messaging(0));
    try {
      final commitments = [
        await _km.nextKeyDigest(next),
        (await _km.postQuantumNext(pqSeed)).digest
      ];
      final anchor = await _km.messagingKeySet(messagingSeed);
      await _post('the messaging keys', '/api/keystore/messaging-seed', {
        'seed_hex': [
          for (final b in messagingSeed) b.toRadixString(16).padLeft(2, '0')
        ].join()
      });
      final expected = ExpectedEvent.founding(
          keys: [key],
          next: commitments,
          witnesses: witnesses,
          toad: toad,
          anchors: [anchor]);
      final prepared = await _prepare('the founding', {
        't': 'icp',
        'k': [key],
        'kt': '1',
        'n': commitments,
        'nt': '1',
        'a': [anchor],
        if (witnesses.isNotEmpty) 'b': witnesses,
        if (witnesses.isNotEmpty) 'bt': toad.toRadixString(16),
      });
      return await _checkSignCommit(
          'the founding',
          expected,
          prepared,
          KeyManager.signingSeed(seed, index: 0),
          WitnessSet(witnesses, witnesses.isEmpty ? 0 : toad),
          reveals: key,
          generation: 0);
    } finally {
      pqSeed.fillRange(0, pqSeed.length, 0);
      messagingSeed.fillRange(0, messagingSeed.length, 0);
    }
  }

  /// Rotates [aid], whose last establishment event revealed the generation
  /// [generation] key, to the generation [generation] + 1 key it committed to,
  /// committing to the generation [generation] + 2 key and the generation
  /// [generation] + 1 post-quantum key. [after] is the place and digest of
  /// the event the rotation follows: the tip, or for a recovery rotation the
  /// last establishment event or a kept interaction, read from this device's
  /// own verified key state, never from the core. [witnessedBy] is the
  /// witness set in force before it. A [recovery] rotation follows the place
  /// the person chose, so it is never moved to the tip on a `tip_moved`.
  Future<Committed> rotate(Uint8List seed,
      {required String aid,
      required int generation,
      required int afterSn,
      required String afterDigest,
      int toad = 0,
      List<String> cuts = const [],
      List<String> adds = const [],
      List<Object?> anchors = const [],
      WitnessSet? witnessedBy,
      bool recovery = false,
      bool afterStepOneOfAMove = false}) async {
    // At stage two a rotation reveals both keys and commits to both again
    // (`kt` and `nt` "2"), and both sign it: the stage is read from the key
    // state, never taken from the caller. [afterStepOneOfAMove] is step 2 of a
    // move to [seed]'s phrase: the keys in force are the old phrase's, and the
    // stage is theirs.
    final pq = await _postQuantumGenerationInForce(seed, aid, generation,
        theKeysInForceAreAnotherPhrases: afterStepOneOfAMove);
    return await _rotate('this rotation',
        revealing: seed,
        revealed: generation + 1,
        committingFrom: seed,
        nextClassical: generation + 2,
        nextPostQuantum: generation + 1,
        revealingPostQuantum: pq == null ? null : generation,
        reCommitWitnessed: pq != null,
        aid: aid,
        afterSn: afterSn,
        afterDigest: afterDigest,
        toad: toad,
        cuts: cuts,
        adds: adds,
        anchors: anchors,
        witnessedBy: witnessedBy,
        recovery: recovery);
  }

  /// The keys the newest establishment event of [aid] names in `k`: from this
  /// device's own record where it made that event (a record made before keys
  /// were kept is of stage one, which is all there was), otherwise from the key
  /// state [readTheKeyState] reads. Null where neither can say.
  Future<List<String>?> _keysInForce(String aid, int generation) async {
    final h = await _held?.read();
    final key = h?.keyInForce;
    if (h != null &&
        h.aid == aid &&
        h.generation == generation &&
        key != null) {
      return h.keysInForce ?? [key];
    }
    final read = readTheKeysInForce ?? readTheKeyState;
    if (read == null) return null;
    final now = await read(aid);
    if (now.generation != generation) {
      throw TheLogKeepsMoving(aid, 0, rotatedElsewhere: true);
    }
    return now.keys;
  }

  /// The generation of the post-quantum key in force for [aid], read from the
  /// key state this device verifies, or null at stage one. At stage two `k`
  /// holds the classical key of [generation] and the post-quantum key of
  /// generation [generation] - 1, and that key must be the one this phrase
  /// derives, or nothing is signed. Without [readTheKeyState] nothing can say
  /// the identity is past stage one, so stage one is what is signed for.
  ///
  /// With [theKeysInForceAreAnotherPhrases] (step 2 of a move to this phrase,
  /// whose predecessor's `k` is the old phrase's), only the stage is read: the
  /// keys in force are not this phrase's to derive, and the event is checked
  /// against the commitment it opens before anything is signed.
  Future<int?> _postQuantumGenerationInForce(
      Uint8List seed, String aid, int generation,
      {bool theKeysInForceAreAnotherPhrases = false}) async {
    final keys = await _keysInForce(aid, generation);
    if (keys == null || keys.length <= 1) return null;
    // Refused before any key is derived while no code is assigned.
    PostQuantumCodes.require('an event of an identity at stage two');
    if (theKeysInForceAreAnotherPhrases) {
      if (keys.length != 2) {
        throw ThePostQuantumKeyInForceIsNotThisPhrases(
            aid,
            'k holds ${keys.length} keys, and only two (a classical key and a '
            'post-quantum one) are a stage a move to this phrase is made from');
      }
      return generation;
    }
    final pq =
        (await thePostQuantumSeedInForce(_km, seed, aid, generation, keys))!;
    pq.fillRange(0, pq.length, 0); // only the generation was wanted
    return generation - 1;
  }

  /// Stage two of a hybrid identity: rotates [aid], whose last establishment
  /// event revealed the generation [generation] key and committed to the
  /// post-quantum key of that generation, revealing both. `k` is the
  /// generation [generation] + 1 classical key and the generation [generation]
  /// post-quantum key, `kt` is "2", and it commits to the generation
  /// [generation] + 2 classical key and the generation [generation] + 1
  /// post-quantum key with `nt` "2". The classical signature is at index 0 and
  /// the post-quantum one at index 1, each opening the prior commitment's
  /// place of the same number. Every event after it needs both signatures.
  ///
  /// Refused ([PostQuantumNotYet]) while [PostQuantumCodes.assigned] is off,
  /// which it is in every release: CESR has assigned no post-quantum code.
  /// [reCommitWitnessed] is whether the re-commit rotation under the assigned
  /// codes has been witnessed ([ExpectedEvent.stageTwoRotation]).
  Future<Committed> rotateToStageTwo(Uint8List seed,
      {required String aid,
      required int generation,
      required int afterSn,
      required String afterDigest,
      required bool reCommitWitnessed,
      int toad = 0,
      List<String> cuts = const [],
      List<String> adds = const [],
      List<Object?> anchors = const [],
      WitnessSet? witnessedBy}) async {
    PostQuantumCodes.require('a stage-two rotation');
    return await _rotate('this stage-two rotation',
        revealing: seed,
        revealed: generation + 1,
        committingFrom: seed,
        nextClassical: generation + 2,
        nextPostQuantum: generation + 1,
        revealingPostQuantum: generation,
        reCommitWitnessed: reCommitWitnessed,
        aid: aid,
        afterSn: afterSn,
        afterDigest: afterDigest,
        toad: toad,
        cuts: cuts,
        adds: adds,
        anchors: anchors,
        witnessedBy: witnessedBy,
        recovery: false);
  }

  /// Step 1 of moving [aid] to a new phrase (ADR-061 section 10): reveals the
  /// old phrase's key generation [generation] + 1, as a routine rotation would,
  /// and commits to the new phrase's classical key 1 and post-quantum
  /// generation 0. The new phrase's own key appears in no `k` until step 2,
  /// which is [rotate] with [newSeed] at generation 0, made as a recovery
  /// rotation after this one so that any interaction a holder of the old
  /// phrase signed in between is superseded.
  ///
  /// At stage two the step reveals the old phrase's classical key and its
  /// post-quantum key in force, commits to the new phrase's classical key 1 and
  /// post-quantum generation 0 with `nt` "2", and is signed by both old keys;
  /// the stage is read from the key state, never given. [beforeSigning] runs
  /// once the core has prepared the event and it has been checked, and before
  /// anything signs it: where the caller keeps the new phrase, so a core that
  /// refuses the step leaves nothing kept.
  Future<Committed> moveToANewPhrase(Uint8List oldSeed, Uint8List newSeed,
      {required String aid,
      required int generation,
      required int afterSn,
      required String afterDigest,
      int toad = 0,
      WitnessSet? witnessedBy,
      Future<void> Function()? beforeSigning}) async {
    if (_sameBytes(oldSeed, newSeed)) {
      throw ArgumentError('the new phrase is the phrase it replaces');
    }
    final pq = await _postQuantumGenerationInForce(oldSeed, aid, generation);
    return await _rotate('moving to a new phrase',
        revealing: oldSeed,
        revealed: generation + 1,
        committingFrom: newSeed,
        nextClassical: 1,
        nextPostQuantum: 0,
        revealingPostQuantum: pq == null ? null : generation,
        reCommitWitnessed: pq != null,
        beforeSigning: beforeSigning,
        aid: aid,
        afterSn: afterSn,
        afterDigest: afterDigest,
        toad: toad,
        witnessedBy: witnessedBy);
  }

  static bool _sameBytes(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var d = 0;
    for (var i = 0; i < a.length; i++) {
      d |= a[i] ^ b[i];
    }
    return d == 0;
  }

  Future<Committed> _rotate(String what,
      {required Uint8List revealing,
      required int revealed,
      required Uint8List committingFrom,
      required int nextClassical,
      required int nextPostQuantum,
      int? revealingPostQuantum,
      bool reCommitWitnessed = false,
      required String aid,
      required int afterSn,
      required String afterDigest,
      int toad = 0,
      List<String> cuts = const [],
      List<String> adds = const [],
      List<Object?> anchors = const [],
      WitnessSet? witnessedBy,
      bool recovery = false,
      Future<void> Function()? beforeSigning}) async {
    return _atTheTip(
        aid,
        (afterSn: afterSn, digest: afterDigest),
        revealed - 1,
        !recovery,
        (tip, before) => _rotateAfter(what,
            revealing: revealing,
            revealed: revealed,
            committingFrom: committingFrom,
            nextClassical: nextClassical,
            nextPostQuantum: nextPostQuantum,
            revealingPostQuantum: revealingPostQuantum,
            reCommitWitnessed: reCommitWitnessed,
            aid: aid,
            afterSn: tip.sn,
            afterDigest: tip.digest,
            toad: toad,
            cuts: cuts,
            adds: adds,
            anchors: anchors,
            set: (before ?? witnessedBy ?? WitnessSet.none)
                .rotated(cuts: cuts, adds: adds, toad: toad),
            recovery: recovery,
            beforeSigning: beforeSigning));
  }

  Future<Committed> _rotateAfter(String what,
      {required Uint8List revealing,
      required int revealed,
      required Uint8List committingFrom,
      required int nextClassical,
      required int nextPostQuantum,
      required int? revealingPostQuantum,
      required bool reCommitWitnessed,
      required String aid,
      required int afterSn,
      required String afterDigest,
      required int toad,
      required List<String> cuts,
      required List<String> adds,
      required List<Object?> anchors,
      required WitnessSet set,
      required bool recovery,
      Future<void> Function()? beforeSigning}) async {
    final key = KeyManager.publicKeyAt(revealing, revealed);
    final next = KeyManager.publicKeyAt(committingFrom, nextClassical);
    final pqSeed = KeyManager.slip10Ed25519(
        committingFrom, KeyPaths.postQuantum(nextPostQuantum));
    // Stage two also reveals the post-quantum key this event's predecessor
    // committed to, and signs with it.
    final revealSeed = revealingPostQuantum == null
        ? null
        : KeyManager.slip10Ed25519(
            revealing, KeyPaths.postQuantum(revealingPostQuantum));
    try {
      final commitments = [
        await _km.nextKeyDigest(next),
        (await _km.postQuantumNext(pqSeed)).digest
      ];
      final revealedPq = revealSeed == null
          ? null
          : (await _km.postQuantumNext(revealSeed)).verkey;
      final sn = afterSn + 1;
      final expected = revealedPq == null
          ? ExpectedEvent.rotation(
              aid: aid,
              sn: sn,
              prior: afterDigest,
              keys: [key],
              next: commitments,
              toad: toad,
              cuts: cuts,
              adds: adds,
              anchors: anchors)
          : ExpectedEvent.stageTwoRotation(
              aid: aid,
              sn: sn,
              prior: afterDigest,
              classicalKey: key,
              postQuantumKey: revealedPq,
              next: commitments,
              reCommitWitnessed: reCommitWitnessed,
              toad: toad,
              cuts: cuts,
              adds: adds,
              anchors: anchors);
      final prepared = await _prepare(what, {
        'aid': aid,
        't': 'rot',
        'k': [key, if (revealedPq != null) revealedPq],
        'kt': revealedPq == null ? '1' : '2',
        'n': commitments,
        'nt': revealedPq == null ? '1' : '2',
        'a': anchors,
        'br': cuts,
        'ba': adds,
        'bt': toad.toRadixString(16),
        'after': {'s': afterSn.toRadixString(16), 'd': afterDigest},
      });
      return await _checkSignCommit(what, expected, prepared,
          KeyManager.signingSeed(revealing, index: revealed), set,
          recovery: recovery,
          reveals: key,
          generation: revealed,
          alsoSignedBy: revealSeed,
          beforeSigning: beforeSigning);
    } finally {
      pqSeed.fillRange(0, pqSeed.length, 0);
      revealSeed?.fillRange(0, revealSeed.length, 0);
    }
  }

  /// Anchors [anchors] in an interaction of [aid] after the event at
  /// [afterSn] with digest [afterDigest], signed by the generation
  /// [generation] key in force. [witnessedBy] is the witness set in force.
  /// At stage two (the key state this device reads has two keys in `k`) the
  /// interaction is signed by the post-quantum key as well, at place 1, and
  /// refused ([PostQuantumNotYet]) while [PostQuantumCodes.assigned] is off.
  /// The stage is read, not given: a caller that forgot a restart could not
  /// have the interaction signed by one key and refused for good.
  Future<Committed> interact(Uint8List seed,
      {required String aid,
      required int generation,
      required int afterSn,
      required String afterDigest,
      required List<Object?> anchors,
      WitnessSet? witnessedBy}) async {
    final postQuantumGeneration =
        await _postQuantumGenerationInForce(seed, aid, generation);
    return await _atTheTip(
        aid,
        (afterSn: afterSn, digest: afterDigest),
        generation,
        true,
        (tip, before) => _interactAfter(seed,
            aid: aid,
            generation: generation,
            afterSn: tip.sn,
            afterDigest: tip.digest,
            anchors: anchors,
            postQuantumGeneration: postQuantumGeneration,
            set: before ?? witnessedBy ?? WitnessSet.none));
  }

  Future<Committed> _interactAfter(Uint8List seed,
      {required String aid,
      required int generation,
      required int afterSn,
      required String afterDigest,
      required List<Object?> anchors,
      required int? postQuantumGeneration,
      required WitnessSet set}) async {
    if (postQuantumGeneration != null) {
      PostQuantumCodes.require('an interaction signed by a post-quantum key');
    }
    final pqSeed = postQuantumGeneration == null
        ? null
        : KeyManager.slip10Ed25519(
            seed, KeyPaths.postQuantum(postQuantumGeneration));
    try {
      return await _interactSigned(seed, pqSeed,
          aid: aid,
          generation: generation,
          afterSn: afterSn,
          afterDigest: afterDigest,
          anchors: anchors,
          set: set);
    } finally {
      pqSeed?.fillRange(0, pqSeed.length, 0);
    }
  }

  Future<Committed> _interactSigned(Uint8List seed, Uint8List? pqSeed,
      {required String aid,
      required int generation,
      required int afterSn,
      required String afterDigest,
      required List<Object?> anchors,
      required WitnessSet set}) async {
    final expected = ExpectedEvent.interaction(
        aid: aid, sn: afterSn + 1, prior: afterDigest, anchors: anchors);
    final prepared = await _prepare('this interaction', {
      'aid': aid,
      't': 'ixn',
      'a': anchors,
      'after': {'s': afterSn.toRadixString(16), 'd': afterDigest},
    });
    return _checkSignCommit('this interaction', expected, prepared,
        KeyManager.signingSeed(seed, index: generation), set,
        alsoSignedBy: pqSeed);
  }

  /// Makes an event after [given], signed by the generation [generation] key
  /// in force, and when the core answers `tip_moved` before anything is
  /// signed, waits, reads the key state again with [readTheKeyState] and
  /// makes it after the tip that reads, with its witnesses, at most
  /// [retryDelays].length times. A key state whose keys in force are not the
  /// generation [generation] ones means another device rotated: it stops.
  Future<Committed> _atTheTip(
      String aid,
      ({int afterSn, String digest}) given,
      int generation,
      bool mayMove,
      Future<Committed> Function(Place after, WitnessSet? witnesses)
          make) async {
    Place after = (sn: given.afterSn, digest: given.digest);
    WitnessSet? witnesses;
    for (var tries = 0;; tries++) {
      try {
        return await make(after, witnesses);
      } on _MovedBeforeSigning catch (moved) {
        final read = readTheKeyState;
        if (!mayMove || read == null) throw moved.refusal;
        if (tries >= retryDelays.length) throw TheLogKeepsMoving(aid, tries);
        await Future<void>.delayed(retryDelays[tries]);
        final now = await read(aid);
        if (now.generation != generation) {
          throw TheLogKeepsMoving(aid, tries + 1, rotatedElsewhere: true);
        }
        after = now.tip;
        witnesses = now.witnesses;
      }
    }
  }

  /// Commits again every event of [aid] this device signed and the core has
  /// not yet acknowledged: what a lost answer or a crash left. Each is
  /// committed with the same bytes and signatures, so at most one event is
  /// ever at a place. One the core added and too few witnesses have yet is
  /// sent to them again; [witnessedBy] is the witness set in force. One the
  /// core refused for good stops this with [AnEventWasRefused], for the
  /// person to see.
  Future<List<Committed>> finishSigned(String aid,
      {WitnessSet? witnessedBy}) async {
    final set = witnessedBy ?? WitnessSet.none;
    final done = <Committed>[];
    for (final r in await _signed.unfinished(aid)) {
      if (!r.signed) continue;
      final what = 'the event at sequence number ${r.sn}';
      final refused = r.refusedWith;
      if (refused != null) {
        throw AnEventWasRefused(
            r, KeyEventRefused(what, 0, refused, 'refused before'));
      }
      done.add(r.recorded
          ? await _seeItWitnessed(r, 'already_recorded', set, coreHasIt: true)
          : await _commit(what, r, set));
    }
    return done;
  }

  /// Lets go of the event at [sn] of [aid] the core refused, as the person
  /// decided, once the witnesses show it is not in the identity's log: enough
  /// of them to meet the threshold of [witnessedBy] must answer, and none may
  /// hold it. Letting go without witnesses to ask needs [withoutWitnesses]:
  /// then nothing but the core says the event is not in the log.
  Future<LetGo> letGoOf(String aid, int sn,
      {WitnessSet? witnessedBy, bool withoutWitnesses = false}) async {
    final set = witnessedBy ?? WitnessSet.none;
    final r = (await _signed.unfinished(aid)).firstWhere(
        (r) => r.sn == sn && r.refusedWith != null,
        orElse: () => throw StateError('this device holds no refused event at '
            'sequence number $sn of $aid'));
    final witnesses = _witnesses;
    if (set.witnesses.isEmpty || witnesses == null) {
      if (!withoutWitnesses) {
        throw StateError('no witness can say whether the event at sequence '
            'number $sn of $aid is in its log');
      }
      await _signed.letGo(r);
      return LetGo.released;
    }
    final held = await witnesses.holdAt(aid: aid, sn: sn, set: set);
    if (held.values.any((h) => h?.digest == r.digest)) {
      // In the log after all: no longer refused, sent on until enough
      // witnesses have it, and committed to the core again when this device
      // next finishes what it signed.
      await _toTheWitnesses(await _signed.refused(r, null), set);
      return LetGo.itIsInTheLog;
    }
    if (held.length < set.toRuleOut) {
      throw StateError('only ${held.length} of the ${set.witnesses.length} '
          'witnesses of $aid showed they do not hold sequence number $sn, '
          'and ${set.toRuleOut} must for it to be in no copy of the log');
    }
    await _signed.letGo(r);
    return LetGo.released;
  }

  Future<String> _prepare(String what, Map<String, Object?> body) async {
    final Map<String, dynamic> res;
    try {
      res = await _post(what, '/api/events/prepare', body);
    } on KeyEventRefused catch (e) {
      if (e.code == 'tip_moved') throw _MovedBeforeSigning(e);
      rethrow;
    }
    final raw = res['raw_b64'];
    if (raw is! String || raw.isEmpty)
      throw KeyEventRefused(what, 200, 'no_event', 'the core prepared nothing');
    return raw;
  }

  Future<Committed> _checkSignCommit(String what, ExpectedEvent expected,
      String rawB64, Uint8List signingSeed, WitnessSet set,
      {bool recovery = false,
      String? reveals,
      int? generation,
      Uint8List? alsoSignedBy,
      Future<void> Function()? beforeSigning}) async {
    try {
      final raw = base64Decode(rawB64);
      final ev = await expected.requireIn(_km, raw);
      await beforeSigning?.call();
      // A founding names the identity this device holds from now on, with
      // where its witnesses are, before anything is signed for it.
      final witnesses = _witnesses;
      if (ev.t == 'icp') {
        await _held?.holds(ev.i, witnessAddresses: {
          for (final w in set.witnesses)
            if (witnesses?.addressOf(w) != null) w: witnesses!.addressOf(w)!
        });
      }
      // A recovery rotation the person asked for supersedes the interactions
      // after the place it follows: none of this device's reservations of
      // interactions there may be committed. Nothing else is superseded, and
      // nothing is before the event is checked.
      if (recovery) await _signed.supersededBy(ev.i, ev.s);
      final reservation = await _signed.reserve(
          aid: ev.i,
          sn: ev.s,
          prior: ev.p,
          digest: ev.d,
          bytesB64: rawB64,
          t: ev.t,
          reveals: reveals,
          generation: generation);
      if (!reservation.signed) {
        final privateKey = ed.newKeyFromSeed(signingSeed);
        final List<int> signature;
        try {
          signature = ed.sign(privateKey, raw);
        } finally {
          privateKey.bytes.fillRange(0, privateKey.bytes.length, 0);
        }
        await _signed.signedWith(
            reservation,
            alsoSignedBy == null
                ? [await _km.signatureByTheOnlyKey(signature)]
                : await _signedByBoth(signature, alsoSignedBy, raw,
                    opensCommitment: ev.t != 'ixn'));
      }
      final signed = (await _signed.unfinished(ev.i))
          .firstWhere((r) => r.sn == ev.s && r.digest == ev.d);
      return await _commit(what, signed, set);
    } finally {
      signingSeed.fillRange(0, signingSeed.length, 0);
    }
  }

  /// The signatures of an event signed by both its classical key and its
  /// post-quantum one ([postQuantumSeed]'s): the classical signature at index 0
  /// and the post-quantum one at index 1. A rotation's each open the place of
  /// the same number in the prior commitment ([opensCommitment]); an
  /// interaction opens no commitment, so its signatures are current-only (keri-go
  /// 3Y for the post-quantum key, B for the classical one).
  Future<List<String>> _signedByBoth(
      List<int> classical, Uint8List postQuantumSeed, List<int> raw,
      {required bool opensCommitment}) async {
    final post = await _km.signMlDsa65(postQuantumSeed, raw);
    return [
      await _km.indexEd25519Signature(classical,
          index: 0, ondex: 0, currentOnly: !opensCommitment),
      await _km.indexMlDsa65Signature(post,
          index: 1, ondex: 1, currentOnly: !opensCommitment),
    ];
  }

  Future<Committed> _commit(String what, Reservation r, WitnessSet set) async {
    final Map<String, dynamic> res;
    try {
      res = await _post(what, '/api/events/commit',
          {'raw_b64': r.bytesB64, 'sigs': r.signatures});
    } on KeyEventRefused catch (e) {
      if (e.code == 'place_taken' || e.code == 'tip_moved') {
        return _confirmTheTakenPlace(r, e, set);
      }
      return _notRecorded(r, e, set);
    } catch (_) {
      // Not answered at all: the event is kept, signed, to commit again, and
      // goes to the witnesses meanwhile.
      await _toTheWitnesses(r, set);
      rethrow;
    }
    final status = '${res['status'] ?? ''}';
    if (status == 'waiting_for_signatures') {
      // The core holds the event for more signers than it was given, which
      // this device cannot add. The event is not recorded, and is treated
      // like any answer that is not "recorded", so the person is never left
      // with a place nothing can release.
      return _notRecorded(
          r,
          KeyEventRefused(what, 202, 'waiting_for_signatures', jsonEncode(res)),
          set);
    }
    return _seeItWitnessed(r, status, set, coreHasIt: true);
  }

  /// The core did not record [r], whatever it said: [r] goes to the witnesses
  /// anyway, and if they receipt it the core is withholding it; an answer that
  /// will be the same however often it is sent ends the event as refused, for
  /// the person to see and let go ([letGoOf]).
  Future<Never> _notRecorded(
      Reservation r, KeyEventRefused e, WitnessSet set) async {
    // Whatever the core answered, the event goes to the witnesses: a core
    // that refuses an event, or fails, after passing it on to some of them
    // would otherwise leave it in their copies unknown to this device.
    final (kept, w) = await _toTheWitnesses(r, set);
    if (w != null && w.receipts.isNotEmpty) {
      throw TheCoreWithholdsThisEvent(kept, e, w);
    }
    if (_forGood(e)) {
      throw AnEventWasRefused(await _signed.refused(kept, e.code), e);
    }
    throw e;
  }

  /// Sends [r] to its witnesses and checks their receipts, marking it
  /// witnessed when enough receipt it, and ending it once the core has it too.
  /// Null where there are no witnesses to ask.
  Future<(Reservation, Witnessed?)> _toTheWitnesses(
      Reservation r, WitnessSet set) async {
    final witnesses = _witnesses;
    if (witnesses == null || set.witnesses.isEmpty) return (r, null);
    final w = await witnesses.receipt(
        aid: r.aid,
        sn: r.sn,
        digest: r.digest,
        bytesB64: r.bytesB64,
        sigs: r.signatures,
        set: set);
    var kept = r;
    if (w.enough && !kept.witnessed) kept = await _signed.witnessed(kept);
    if (kept.recorded && kept.witnessed) await _signed.committed(kept);
    return (kept, w);
  }

  /// An event the core has: sent to its witnesses, and ended once enough of
  /// them have it too (at once, where there are none to ask).
  Future<Committed> _seeItWitnessed(
      Reservation r, String status, WitnessSet set,
      {required bool coreHasIt}) async {
    var kept = r;
    if (coreHasIt && !kept.recorded) kept = await _signed.recorded(kept);
    if (coreHasIt) await _remember(kept, set);
    final (after, w) = await _toTheWitnesses(kept, set);
    if (w == null) await _signed.committed(after);
    return Committed(r.aid, r.sn, r.digest, status, r.bytesB64, r.signatures,
        witnessed: w);
  }

  /// Records [r], which its core holds, in this device's own record, where
  /// that record is of [r]'s identity.
  Future<void> _remember(Reservation r, WitnessSet set) async {
    final held = _held;
    if (held == null || (await held.read())?.aid != r.aid) return;
    final parsed = await _km.parseEvent(base64Decode(r.bytesB64));
    final ilk = r.t ?? parsed.t;
    // The keys an establishment event names, so the stage the identity is at
    // is known from this record without asking anybody.
    final k = ilk == 'ixn'
        ? null
        : [
            for (final f in parsed.fields)
              if (f.name == 'k')
                for (final key in (f.value as List)) '$key'
          ];
    await held.made(
        aid: r.aid,
        at: (sn: r.sn, digest: r.digest),
        ilk: ilk,
        key: r.key,
        keys: k,
        generation: r.generation,
        witnesses: set.witnesses,
        toad: set.toad);
  }

  /// The core said another event holds [r]'s place, or that the log moved
  /// past it. Believed only when enough witnesses that the rest could not
  /// establish [r] hold a different event there, in a log that verifies, and
  /// that event is one [r] cannot supersede: an establishment event, or any
  /// event where [r] is an interaction. Otherwise [r] goes to the witnesses
  /// itself, and is kept.
  Future<Committed> _confirmTheTakenPlace(
      Reservation r, KeyEventRefused refusal, WitnessSet set) async {
    final witnesses = _witnesses;
    if (witnesses == null || set.witnesses.isEmpty) throw refusal;
    final ours = r.t ?? (await _km.parseEvent(base64Decode(r.bytesB64))).t;
    final held = await witnesses.holdAt(aid: r.aid, sn: r.sn, set: set);
    final others = {
      for (final e in held.entries)
        if (e.value != null &&
            e.value!.digest != r.digest &&
            (e.value!.establishment || ours == 'ixn'))
          e.key: e.value!.digest
    };
    if (others.length >= set.toRuleOut) {
      await _signed.letGo(r);
      throw ThePlaceIsTaken(r.aid, r.sn, others);
    }
    final (kept, w) = await _toTheWitnesses(r, set);
    throw TheCoreWithholdsThisEvent(kept, refusal, w!);
  }

  /// Whether a refusal will be the same however often the event is sent:
  /// anything the core decided from the event itself, as opposed to a fault,
  /// a lapsed sign-in or a busy core.
  static bool _forGood(KeyEventRefused e) =>
      e.code == 'waiting_for_signatures' ||
      (e.statusCode >= 400 &&
          e.statusCode < 500 &&
          !const {401, 408, 409, 425, 429}.contains(e.statusCode));

  Future<Map<String, dynamic>> _post(
      String what, String path, Map<String, Object?> body) async {
    final res = await _client.post(Uri.parse('$_baseUrl$path'),
        headers: const {'Content-Type': 'application/json'},
        body: jsonEncode(body));
    Map<String, dynamic> decoded = const {};
    try {
      final d = jsonDecode(res.body);
      if (d is Map<String, dynamic>) decoded = d;
    } catch (_) {}
    if (res.statusCode < 200 || res.statusCode > 299) {
      throw KeyEventRefused(
          what, res.statusCode, '${decoded['error'] ?? ''}', res.body);
    }
    return decoded;
  }
}

/// A `tip_moved` before anything was signed: safe to prepare again.
class _MovedBeforeSigning implements Exception {
  _MovedBeforeSigning(this.refusal);
  final KeyEventRefused refusal;
}
