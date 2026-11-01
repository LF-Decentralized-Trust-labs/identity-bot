import 'dart:convert';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;

import '../crypto/keys.dart';
import 'key_math.dart';
import 'signing_an_event.dart';
import 'the_event_this_device_expects.dart';
import 'the_events_this_device_signed.dart';

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

/// An event this device committed: its identifier, place and digest, and
/// whether the core added it or holds it for further signers.
class Committed {
  Committed(this.aid, this.sn, this.digest, this.status, this.bytesB64,
      this.signatures);
  final String aid;
  final int sn;
  final String digest;

  /// `recorded`, `already_recorded` when the core had it already, or `held`
  /// while further signers' signatures are awaited.
  final String status;
  final String bytesB64;
  final List<String> signatures;
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
class TheKeyEventsThisDeviceMakes {
  TheKeyEventsThisDeviceMakes(this._client, this._baseUrl, this._km,
      {TheEventsThisDeviceSigned? signed})
      : _signed = signed ?? TheEventsThisDeviceSigned();

  final http.Client _client;
  final String _baseUrl;
  final KeyMath _km;
  final TheEventsThisDeviceSigned _signed;

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
      return await _checkSignCommit('the founding', expected, prepared,
          KeyManager.signingSeed(seed, index: 0));
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
  /// own verified key state, never from the core.
  Future<Committed> rotate(Uint8List seed,
      {required String aid,
      required int generation,
      required int afterSn,
      required String afterDigest,
      int toad = 0,
      List<String> cuts = const [],
      List<String> adds = const [],
      List<Object?> anchors = const []}) async {
    final key = KeyManager.keyAt(seed, generation + 1).publicKeyEncoded;
    final next = KeyManager.keyAt(seed, generation + 2).publicKeyEncoded;
    final pqSeed =
        KeyManager.slip10Ed25519(seed, KeyPaths.postQuantum(generation + 1));
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
      final prepared = await _prepare('this rotation', {
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
      return await _checkSignCommit('this rotation', expected, prepared,
          KeyManager.signingSeed(seed, index: generation + 1));
    } finally {
      pqSeed.fillRange(0, pqSeed.length, 0);
    }
  }

  /// Anchors [anchors] in an interaction of [aid] after the event at
  /// [afterSn] with digest [afterDigest], signed by the generation
  /// [generation] key in force.
  Future<Committed> interact(Uint8List seed,
      {required String aid,
      required int generation,
      required int afterSn,
      required String afterDigest,
      required List<Object?> anchors}) async {
    final expected = ExpectedEvent.interaction(
        aid: aid, sn: afterSn + 1, prior: afterDigest, anchors: anchors);
    final prepared = await _prepare('this interaction', {
      'aid': aid,
      't': 'ixn',
      'a': anchors,
      'after': {'s': afterSn.toRadixString(16), 'd': afterDigest},
    });
    return _checkSignCommit('this interaction', expected, prepared,
        KeyManager.signingSeed(seed, index: generation));
  }

  /// Commits again every event of [aid] this device signed and the core has
  /// not yet acknowledged: what a lost answer or a crash left. Each is
  /// committed with the same bytes and signatures, so at most one event is
  /// ever at a place.
  Future<List<Committed>> finishSigned(String aid) async {
    final done = <Committed>[];
    for (final r in await _signed.unfinished(aid)) {
      if (!r.signed) continue;
      done.add(await _commit('the event at sequence number ${r.sn}', r));
    }
    return done;
  }

  Future<String> _prepare(String what, Map<String, Object?> body) async {
    final res = await _post(what, '/api/events/prepare', body);
    final raw = res['raw_b64'];
    if (raw is! String || raw.isEmpty)
      throw KeyEventRefused(what, 200, 'no_event', 'the core prepared nothing');
    return raw;
  }

  Future<Committed> _checkSignCommit(String what, ExpectedEvent expected,
      String rawB64, Uint8List signingSeed) async {
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
      return await _commit(what, signed);
    } finally {
      signingSeed.fillRange(0, signingSeed.length, 0);
    }
  }

  Future<Committed> _commit(String what, Reservation r) async {
    final res = await _post(what, '/api/events/commit',
        {'raw_b64': r.bytesB64, 'sigs': r.signatures});
    await _signed.committed(r);
    return Committed(r.aid, r.sn, r.digest, '${res['status'] ?? ''}',
        r.bytesB64, r.signatures);
  }

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
