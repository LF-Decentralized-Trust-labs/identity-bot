import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../crypto/keys.dart';
import 'key_math.dart';
import 'the_identity_this_device_holds.dart';
import 'the_key_events_this_device_makes.dart';
import 'the_key_state_this_device_reads.dart';

/// What recovery found and installed.
class RecoveredIdentity {
  RecoveredIdentity(this.state, this.messagingGeneration);

  /// The key state recovered, corroborated by the witnesses.
  final VerifiedKeyState state;

  /// The generation of this phrase's messaging keyset the log anchors last:
  /// the one the identity is reached on, whose seed the core was handed.
  final int messagingGeneration;
}

/// Recovery could not finish: what was found, and why it stops.
class RecoveryStopped implements Exception {
  RecoveryStopped(this.why);
  final String why;
  @override
  String toString() => 'recovery stopped: $why';
}

/// Recovering an identity onto a device that has nothing of it but the phrase
/// (ADR-061 section 10).
///
/// The phrase alone does not name the identity: its identifier depends on the
/// witnesses chosen at founding, so recovery takes one public locator, the
/// identifier, with where its witnesses are and, where known, the Identity
/// Agent that keeps its log. Then:
///  1. the log is read from enough witnesses to meet their threshold, and from
///     the Identity Agent, each copy verified on this device and combined as
///     section 9 says: two histories stop recovery;
///  2. every establishment event from this phrase's first is checked to reveal
///     this phrase's keys at consecutive positions, giving the key in force,
///     and the messaging generation the log anchors last is found by deriving;
///  3. the log, as signed, is installed in this device's core, which verifies
///     the whole chain again, and the core is handed that messaging seed;
///  4. this device's record starts from the log's tip.
class RecoveringThisIdentity {
  RecoveringThisIdentity(this._client, this._coreBase, this._km,
      {TheIdentityThisDeviceHolds? held})
      : _held = held ?? TheIdentityThisDeviceHolds();

  final http.Client _client;

  /// This device's core, which the identity is installed in.
  final String _coreBase;
  final KeyMath _km;
  final TheIdentityThisDeviceHolds _held;

  /// How many messaging generations are tried when matching the anchored
  /// keyset to this phrase.
  static const messagingGenerationsTried = 64;

  /// Recovers [aid] from the phrase whose 64-byte BIP39 seed is [seed], its
  /// witnesses reached at [witnessAddresses], and, where given, the Identity
  /// Agent at [agentBase] that keeps its log.
  Future<RecoveredIdentity> recover(Uint8List seed,
      {required String aid,
      required Map<String, Uri> witnessAddresses,
      String agentBase = ''}) async {
    final already = await _held.read();
    if (already != null && already.aid != aid) {
      throw RecoveryStopped('this device already holds ${already.aid}');
    }
    await _held.holds(aid, witnessAddresses: witnessAddresses);

    // 1 and 2: the copies, combined; the key in force, from this phrase.
    final state =
        await TheKeyStateThisDeviceReads(_client, _km, agentBase, held: _held)
            .readTheCopies(seed);
    final log = state.log;
    if (!state.corroborated || log == null) {
      throw RecoveryStopped('too few of the identity\'s witnesses could be '
          'read to corroborate its log');
    }
    if (state.movingToThisPhrase) {
      throw RecoveryStopped(
          'the identity is moving to this phrase and the move '
          'is unfinished; it is finished from the device holding the old one');
    }
    final signed = log.signed;
    if (signed == null || signed.length != log.events.length) {
      throw RecoveryStopped('no copy that reaches the log\'s end came with its '
          'events as signed');
    }

    // The messaging generation the log anchors last.
    final anchored = [
      for (final e in log.events) ...e.messagingKeysets,
    ];
    if (anchored.isEmpty) {
      throw RecoveryStopped('the log anchors no messaging keyset');
    }
    final g = await _messagingGenerationOf(seed, anchored.last);
    if (g == null) {
      throw RecoveryStopped('the messaging keyset the log anchors last is not '
          'one this phrase derives; it predates the fixed branch and is '
          'migrated first (ADR-061 section 8)');
    }

    // 3: installed, and the messaging seed handed over.
    final res = await _client.post(Uri.parse('$_coreBase/api/identity/restore'),
        headers: const {'Content-Type': 'application/json'},
        body: jsonEncode({
          'aid': aid,
          'events': [for (final c in signed) c.toJson()]
        }));
    if (res.statusCode < 200 || res.statusCode > 299) {
      throw KeyEventRefused(
          'installing the identity', res.statusCode, _code(res.body), res.body);
    }
    final messagingSeed = KeyManager.slip10Ed25519(seed, KeyPaths.messaging(g));
    try {
      final m = await _client.post(
          Uri.parse('$_coreBase/api/keystore/messaging-seed'),
          headers: const {'Content-Type': 'application/json'},
          body: jsonEncode({
            'seed_hex': [
              for (final b in messagingSeed) b.toRadixString(16).padLeft(2, '0')
            ].join()
          }));
      if (m.statusCode < 200 || m.statusCode > 299) {
        throw KeyEventRefused(
            'the messaging keys', m.statusCode, _code(m.body), m.body);
      }
    } finally {
      messagingSeed.fillRange(0, messagingSeed.length, 0);
    }

    // 4: readTheCopies has started this device's record from the tip.
    return RecoveredIdentity(state, g);
  }

  /// The generation of this phrase's messaging keyset that is [anchor], or
  /// null.
  Future<int?> _messagingGenerationOf(
      Uint8List seed, Map<String, dynamic> anchor) async {
    final want = _canonical(anchor);
    for (var g = 0; g < messagingGenerationsTried; g++) {
      final s = KeyManager.slip10Ed25519(seed, KeyPaths.messaging(g));
      try {
        if (_canonical(await _km.messagingKeySet(s)) == want) return g;
      } finally {
        s.fillRange(0, s.length, 0);
      }
    }
    return null;
  }

  static String _canonical(Object? v) {
    if (v is Map) {
      final keys = v.keys.map((k) => '$k').toList()..sort();
      return '{${[
        for (final k in keys) '${jsonEncode(k)}:${_canonical(v[k])}'
      ].join(',')}}';
    }
    if (v is List) return '[${v.map(_canonical).join(',')}]';
    return jsonEncode(v);
  }

  static String _code(String body) {
    try {
      final j = jsonDecode(body);
      if (j is Map) return '${j['error'] ?? ''}';
    } catch (_) {}
    return '';
  }
}
