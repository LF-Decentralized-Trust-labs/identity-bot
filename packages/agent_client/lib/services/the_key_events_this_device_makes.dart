import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;

import '../crypto/keys.dart';
import 'key_math.dart';
import 'signing_an_event.dart';
import 'the_event_this_device_expects.dart';
import 'the_events_this_device_signed.dart';
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
/// prepared after it, another event had taken the place. A phrase in use on
/// another device does that; signing stops and the person is told.
class TheLogKeepsMoving implements Exception {
  TheLogKeepsMoving(this.aid, this.tries);
  final String aid;
  final int tries;
  @override
  String toString() => 'the log of $aid moved under this device $tries times; '
      'this phrase may be in use on another device';
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

/// Where an identity's log ends: the place and digest of its last event.
typedef Tip = ({int sn, String digest});

/// An event this device committed: its identifier, place and digest, and
/// whether the core added it or holds it for further signers.
class Committed {
  Committed(this.aid, this.sn, this.digest, this.status, this.bytesB64,
      this.signatures,
      {this.witnessed});
  final String aid;
  final int sn;
  final String digest;

  /// `recorded`, `already_recorded` when the core had it already, or `held`
  /// while further signers' signatures are awaited.
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
/// it. A `tip_moved` before signing is prepared again after the place
/// [readTheTip] reads, at most [retryDelays].length times. A refusal for good
/// is kept and shown, and only the person lets the event go ([letGoOf]).
class TheKeyEventsThisDeviceMakes {
  TheKeyEventsThisDeviceMakes(this._client, this._baseUrl, this._km,
      {TheEventsThisDeviceSigned? signed,
      TheWitnessesOfThisDevicesEvents? witnesses,
      this.readTheTip,
      this.retryDelays = const [
        Duration(seconds: 1),
        Duration(seconds: 2),
        Duration(seconds: 4)
      ]})
      : _signed = signed ?? TheEventsThisDeviceSigned(),
        _witnesses = witnesses;

  final http.Client _client;
  final String _baseUrl;
  final KeyMath _km;
  final TheEventsThisDeviceSigned _signed;
  final TheWitnessesOfThisDevicesEvents? _witnesses;

  /// Reads where an identity's log ends, from this device's own verified key
  /// state, never from the core's say-so; null means a `tip_moved` is not
  /// retried.
  final Future<Tip> Function(String aid)? readTheTip;

  /// The waits before each retry of a `tip_moved`.
  final List<Duration> retryDelays;

  /// Founds an identity on the keys [seed] (the phrase's BIP-39 seed) derives:
  /// the generation 0 signing key, committing to the generation 1 key and the
  /// generation 0 post-quantum key, and anchoring the generation 0 messaging
  /// keyset, whose seed the core is handed first so it can hold those keys.
  Future<Committed> found(Uint8List seed,
      {List<String> witnesses = const [], int toad = 0}) async {
    final key = KeyManager.keyAt(seed, 0).publicKeyEncoded;
    final next = KeyManager.keyAt(seed, 1).publicKeyEncoded;
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
          WitnessSet(witnesses, witnesses.isEmpty ? 0 : toad));
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
          bool recovery = false}) =>
      _rotate('this rotation',
          revealing: seed,
          revealed: generation + 1,
          committingFrom: seed,
          nextClassical: generation + 2,
          nextPostQuantum: generation + 1,
          aid: aid,
          afterSn: afterSn,
          afterDigest: afterDigest,
          toad: toad,
          cuts: cuts,
          adds: adds,
          anchors: anchors,
          witnessedBy: witnessedBy,
          recovery: recovery);

  /// Step 1 of moving [aid] to a new phrase (ADR-061 section 10): reveals the
  /// old phrase's key generation [generation] + 1, as a routine rotation would,
  /// and commits to the new phrase's classical key 1 and post-quantum
  /// generation 0. The new phrase's own key appears in no `k` until step 2,
  /// which is [rotate] with [newSeed] at generation 0, made as a recovery
  /// rotation after this one so that any interaction a holder of the old
  /// phrase signed in between is superseded.
  Future<Committed> moveToANewPhrase(Uint8List oldSeed, Uint8List newSeed,
      {required String aid,
      required int generation,
      required int afterSn,
      required String afterDigest,
      int toad = 0,
      WitnessSet? witnessedBy}) async {
    if (_sameBytes(oldSeed, newSeed)) {
      throw ArgumentError('the new phrase is the phrase it replaces');
    }
    return await _rotate('moving to a new phrase',
        revealing: oldSeed,
        revealed: generation + 1,
        committingFrom: newSeed,
        nextClassical: 1,
        nextPostQuantum: 0,
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
      required String aid,
      required int afterSn,
      required String afterDigest,
      int toad = 0,
      List<String> cuts = const [],
      List<String> adds = const [],
      List<Object?> anchors = const [],
      WitnessSet? witnessedBy,
      bool recovery = false}) async {
    final after = (witnessedBy ?? WitnessSet.none)
        .rotated(cuts: cuts, adds: adds, toad: toad);
    return _atTheTip(
        aid,
        (afterSn: afterSn, digest: afterDigest),
        !recovery,
        (tip) => _rotateAfter(what,
            revealing: revealing,
            revealed: revealed,
            committingFrom: committingFrom,
            nextClassical: nextClassical,
            nextPostQuantum: nextPostQuantum,
            aid: aid,
            afterSn: tip.sn,
            afterDigest: tip.digest,
            toad: toad,
            cuts: cuts,
            adds: adds,
            anchors: anchors,
            set: after));
  }

  Future<Committed> _rotateAfter(String what,
      {required Uint8List revealing,
      required int revealed,
      required Uint8List committingFrom,
      required int nextClassical,
      required int nextPostQuantum,
      required String aid,
      required int afterSn,
      required String afterDigest,
      required int toad,
      required List<String> cuts,
      required List<String> adds,
      required List<Object?> anchors,
      required WitnessSet set}) async {
    final key = KeyManager.keyAt(revealing, revealed).publicKeyEncoded;
    final next =
        KeyManager.keyAt(committingFrom, nextClassical).publicKeyEncoded;
    final pqSeed = KeyManager.slip10Ed25519(
        committingFrom, KeyPaths.postQuantum(nextPostQuantum));
    try {
      final commitments = [
        await _km.nextKeyDigest(next),
        (await _km.postQuantumNext(pqSeed)).digest
      ];
      final sn = afterSn + 1;
      final expected = ExpectedEvent.rotation(
          aid: aid,
          sn: sn,
          prior: afterDigest,
          keys: [key],
          next: commitments,
          toad: toad,
          cuts: cuts,
          adds: adds,
          anchors: anchors);
      final prepared = await _prepare(what, {
        'aid': aid,
        't': 'rot',
        'k': [key],
        'kt': '1',
        'n': commitments,
        'nt': '1',
        'a': anchors,
        'br': cuts,
        'ba': adds,
        'bt': toad.toRadixString(16),
        'after': {'s': afterSn.toRadixString(16), 'd': afterDigest},
      });
      // A rotation that follows a kept interaction supersedes the events
      // after it: none of this device's reservations there may be committed.
      await _signed.supersededBy(aid, sn);
      return await _checkSignCommit(what, expected, prepared,
          KeyManager.signingSeed(revealing, index: revealed), set);
    } finally {
      pqSeed.fillRange(0, pqSeed.length, 0);
    }
  }

  /// Anchors [anchors] in an interaction of [aid] after the event at
  /// [afterSn] with digest [afterDigest], signed by the generation
  /// [generation] key in force. [witnessedBy] is the witness set in force.
  Future<Committed> interact(Uint8List seed,
          {required String aid,
          required int generation,
          required int afterSn,
          required String afterDigest,
          required List<Object?> anchors,
          WitnessSet? witnessedBy}) =>
      _atTheTip(
          aid,
          (afterSn: afterSn, digest: afterDigest),
          true,
          (tip) => _interactAfter(seed,
              aid: aid,
              generation: generation,
              afterSn: tip.sn,
              afterDigest: tip.digest,
              anchors: anchors,
              set: witnessedBy ?? WitnessSet.none));

  Future<Committed> _interactAfter(Uint8List seed,
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
        KeyManager.signingSeed(seed, index: generation), set);
  }

  /// Makes an event after [given], and when the core answers `tip_moved`
  /// before anything is signed, waits, reads the tip again with [readTheTip]
  /// and makes it after that, at most [retryDelays].length times.
  Future<Committed> _atTheTip(String aid, ({int afterSn, String digest}) given,
      bool mayMove, Future<Committed> Function(Tip after) make) async {
    Tip after = (sn: given.afterSn, digest: given.digest);
    for (var tries = 0;; tries++) {
      try {
        return await make(after);
      } on _MovedBeforeSigning catch (moved) {
        final read = readTheTip;
        if (!mayMove || read == null) throw moved.refusal;
        if (tries >= retryDelays.length) throw TheLogKeepsMoving(aid, tries);
        await Future<void>.delayed(retryDelays[tries]);
        after = await read(aid);
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
          ? await _seeItWitnessed(r, 'already_recorded', set)
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
    final r = (await _signed.unfinished(aid)).firstWhere((r) => r.sn == sn,
        orElse: () => throw StateError(
            'this device holds no event at sequence number $sn of $aid'));
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
    if (held.values.contains(r.digest)) {
      await _signed.committed(r);
      return LetGo.itIsInTheLog;
    }
    if (held.length < max(set.toad, 1)) {
      throw StateError('only ${held.length} of the witnesses of $aid answered '
          'for sequence number $sn, and ${max(set.toad, 1)} must');
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
      String rawB64, Uint8List signingSeed, WitnessSet set) async {
    try {
      final raw = base64Decode(rawB64);
      final ev = await expected.requireIn(_km, raw);
      final reservation = await _signed.reserve(
          aid: ev.i, sn: ev.s, prior: ev.p, digest: ev.d, bytesB64: rawB64);
      if (!reservation.signed) {
        final signature = ed.sign(ed.newKeyFromSeed(signingSeed), raw);
        final cesr = await cesrEncodeSignature(_client, _baseUrl, signature);
        await _signed.signedWith(reservation, [cesr]);
      }
      final signed = (await _signed.unfinished(ev.i))
          .firstWhere((r) => r.sn == ev.s && r.digest == ev.d);
      return await _commit(what, signed, set);
    } finally {
      signingSeed.fillRange(0, signingSeed.length, 0);
    }
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
      if (_forGood(e)) {
        throw AnEventWasRefused(await _signed.refused(r, e.code), e);
      }
      rethrow;
    }
    return _seeItWitnessed(r, '${res['status'] ?? ''}', set);
  }

  /// Sends a committed event to its witnesses and checks their receipts; it is
  /// kept until enough have receipted it.
  Future<Committed> _seeItWitnessed(
      Reservation r, String status, WitnessSet set) async {
    final witnesses = _witnesses;
    if (witnesses == null || set.witnesses.isEmpty) {
      await _signed.committed(r);
      return Committed(r.aid, r.sn, r.digest, status, r.bytesB64, r.signatures);
    }
    final kept = r.recorded ? r : await _signed.recorded(r);
    final w = await witnesses.receipt(
        aid: r.aid,
        sn: r.sn,
        digest: r.digest,
        bytesB64: r.bytesB64,
        sigs: r.signatures,
        set: set);
    if (w.enough) await _signed.committed(kept);
    return Committed(r.aid, r.sn, r.digest, status, r.bytesB64, r.signatures,
        witnessed: w);
  }

  /// The core said another event holds [r]'s place, or that the log moved
  /// past it. Believed only when enough witnesses hold a different event
  /// there, in a log that verifies; otherwise [r] goes to the witnesses
  /// itself, and is kept.
  Future<Committed> _confirmTheTakenPlace(
      Reservation r, KeyEventRefused refusal, WitnessSet set) async {
    final witnesses = _witnesses;
    if (witnesses == null || set.witnesses.isEmpty) throw refusal;
    final held = await witnesses.holdAt(aid: r.aid, sn: r.sn, set: set);
    final others = {
      for (final e in held.entries)
        if (e.value != null && e.value != r.digest) e.key: e.value!
    };
    if (others.length >= max(set.toad, 1)) {
      await _signed.letGo(r);
      throw ThePlaceIsTaken(r.aid, r.sn, others);
    }
    final kept = r.recorded ? r : await _signed.recorded(r);
    final w = await witnesses.receipt(
        aid: r.aid,
        sn: r.sn,
        digest: r.digest,
        bytesB64: r.bytesB64,
        sigs: r.signatures,
        set: set);
    if (w.enough) await _signed.committed(kept);
    throw TheCoreWithholdsThisEvent(kept, refusal, w);
  }

  /// Whether a refusal will be the same however often the event is sent:
  /// anything the core decided from the event itself, as opposed to a fault,
  /// a lapsed sign-in or a busy core.
  static bool _forGood(KeyEventRefused e) =>
      e.statusCode >= 400 &&
      e.statusCode < 500 &&
      !const {401, 408, 409, 425, 429}.contains(e.statusCode);

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
