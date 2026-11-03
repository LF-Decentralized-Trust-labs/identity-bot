import 'dart:async';
import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'profile_scope.dart';

/// A place in an identity's log: a sequence number and the digest there.
typedef Place = ({int sn, String digest});

/// What this device knows of the identity whose keys it holds, from what it
/// made itself (ADR-061 section 9, source 1).
class HeldIdentity {
  HeldIdentity._(this._j);

  final Map<String, dynamic> _j;

  /// The identity's identifier. It is public.
  String get aid => _j['aid'] as String;

  /// Where each of its witnesses is reached, by witness: those it was founded
  /// with, or agreed to later.
  Map<String, Uri> get witnessAddresses => {
        for (final e in (_j['witnesses'] as Map? ?? const {}).entries)
          '${e.key}': Uri.parse('${e.value}')
      };

  /// The newest establishment event this device made, or null before it has
  /// made one in this record.
  Place? get establishment => _place('est');

  /// The key that event revealed, and which generation of the phrase that
  /// signed it it was.
  String? get keyInForce => (_j['est'] as Map?)?['key'] as String?;
  int? get generation => ((_j['est'] as Map?)?['g'] as num?)?.toInt();

  /// The newest event this device made that its core holds: where its next
  /// event follows.
  Place? get tip => _place('tip');

  /// The witnesses in force after the newest event, and their threshold.
  List<String> get witnesses =>
      [for (final w in (_j['set'] as List? ?? const [])) '$w'];
  int get toad => (_j['toad'] as num?)?.toInt() ?? 0;

  /// Every key this device revealed in an establishment event, oldest first.
  List<String> get keysRevealed =>
      [for (final k in (_j['keys'] as List? ?? const [])) '$k'];

  Place? _place(String name) {
    final p = _j[name];
    if (p is! Map) return null;
    return (sn: (p['s'] as num).toInt(), digest: p['d'] as String);
  }
}

/// This device's own record of its identity: the identifier, where its
/// witnesses are, and the newest events it made (ADR-061 section 9).
///
/// Only a holder of the phrase can add an establishment event, so the newest
/// one this device made is the key in force unless the phrase has been used
/// elsewhere, and its key state is read from here without asking anybody. The
/// witnesses are read when this cannot answer: on first use, after recovery,
/// and when a signature is refused as stale.
class TheIdentityThisDeviceHolds {
  TheIdentityThisDeviceHolds({FlutterSecureStorage? storage})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
              mOptions: MacOsOptions(useDataProtectionKeyChain: false),
            );

  final FlutterSecureStorage _storage;
  static const _name = 'identity_held';

  static Future<void> _tail = Future.value();
  static Future<T> _serialised<T>(Future<T> Function() op) {
    final result = _tail.then((_) => op());
    _tail = result.then((_) {}, onError: (_) {});
    return result;
  }

  Future<Map<String, dynamic>?> _load(String key) async {
    final raw = await _storage.read(key: key);
    if (raw == null || raw.isEmpty) return null;
    return Map<String, dynamic>.from(jsonDecode(raw) as Map);
  }

  /// The identity this device holds, or null when it holds none.
  Future<HeldIdentity?> read() async {
    final key = await ProfileScope.key(_name);
    return _serialised(() async {
      final j = await _load(key);
      return j == null ? null : HeldIdentity._(j);
    });
  }

  /// Records that this device holds [aid], with its witnesses reached at
  /// [witnessAddresses]. An identity already recorded under another
  /// identifier is refused: a device holds one.
  Future<void> holds(String aid,
          {Map<String, Uri> witnessAddresses = const {}}) =>
      _change((j) {
        if (j['aid'] != null && j['aid'] != aid) {
          throw StateError('this device already holds ${j['aid']}, not $aid');
        }
        j['aid'] = aid;
        final known = Map<String, dynamic>.from(j['witnesses'] as Map? ?? {});
        for (final e in witnessAddresses.entries) {
          known[e.key] = '${e.value}';
        }
        j['witnesses'] = known;
      });

  /// Records an event of the identity's log this device made and its core
  /// holds: its place, and for an establishment event the key it revealed,
  /// that key's generation, and the witnesses in force after it.
  Future<void> made(
          {required String aid,
          required Place at,
          required String ilk,
          String? key,
          int? generation,
          required List<String> witnesses,
          required int toad}) =>
      _change((j) {
        if (j['aid'] != aid) {
          throw StateError('this device does not hold $aid');
        }
        final tip = j['tip'] as Map?;
        if (tip == null || (tip['s'] as num) <= at.sn) {
          j['tip'] = {'s': at.sn, 'd': at.digest};
          j['set'] = witnesses;
          j['toad'] = toad;
        }
        if (ilk != 'ixn') {
          final est = j['est'] as Map?;
          if (est == null || (est['s'] as num) <= at.sn) {
            j['est'] = {
              's': at.sn,
              'd': at.digest,
              'key': key,
              'g': generation
            };
          }
          final keys = List<Object?>.from(j['keys'] as List? ?? const []);
          if (key != null && !keys.contains(key)) keys.add(key);
          j['keys'] = keys;
        }
      });

  /// Replaces what this device takes as the key state with [establishment],
  /// revealing [key] of generation [generation], and [tip], read from
  /// verified copies of the log because this record could not answer.
  Future<void> readFromCopies(
          {required String aid,
          required Place establishment,
          required String key,
          required int generation,
          required Place tip,
          required List<String> witnesses,
          required int toad}) =>
      _change((j) {
        if (j['aid'] != aid) {
          throw StateError('this device does not hold $aid');
        }
        j['est'] = {
          's': establishment.sn,
          'd': establishment.digest,
          'key': key,
          'g': generation
        };
        j['tip'] = {'s': tip.sn, 'd': tip.digest};
        j['set'] = witnesses;
        j['toad'] = toad;
      });

  /// Forgets where the log ends, so the next read asks the witnesses: after a
  /// signature is refused as stale, or a commit whose outcome is unknown. The
  /// newest establishment event this device made is kept: copies that do not
  /// hold it are behind this device, and are not signed after.
  Future<void> forgetTheTip() => _change((j) {
        j.remove('tip');
      });

  Future<void> _change(void Function(Map<String, dynamic> j) change) async {
    final key = await ProfileScope.key(_name);
    await _serialised(() async {
      final j = await _load(key) ?? <String, dynamic>{};
      change(j);
      await _storage.write(key: key, value: jsonEncode(j));
    });
  }
}
