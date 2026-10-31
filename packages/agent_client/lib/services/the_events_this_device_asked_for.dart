import 'dart:async';
import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'profile_scope.dart';

/// A request this device has written down before sending: the entry's id and
/// the profile's storage, both fixed when it was asked, so a profile switch
/// mid-operation cannot move it.
class AskedEvent {
  AskedEvent._(this.id, this.storageKey);
  final String id;
  final String storageKey;
}

/// The events of its identity's key log this device asked the core to add,
/// kept in secure storage until each is signed.
///
/// An event is added first and signed second, so an event this device asked
/// for can be left unsigned if the connection drops between the two, and is
/// signed later (TheKeyInForce.finishStrandedEvents). That later signing must
/// be of an event this device asked for and nothing else: the core supplies
/// both the log and the bytes, so a core, or a remote Identity Agent this app
/// is only the front end for, could otherwise append an event of its own
/// choosing, mark it unsigned, and have this device sign it — a rotation
/// committing to somebody else's next key would hand them the identity.
///
/// Each request is written here BEFORE it is sent, with what was asked
/// (which keys, which anchors) and the sequence number the event must have
/// (the tip plus one), and then the sequence number and digest the core says
/// it added. An event is recognised by its sequence number and digest, or,
/// where the answer never arrived, by what was asked AT that expected
/// sequence number only. A request whose answer never arrived is dropped once
/// the log holds a signed event at or past that number: its place is taken.
///
/// A credential issuance is written down with nothing asked, because the
/// anchor is built by the core, so it is only ever recognised by the sequence
/// number and digest of the answer.
///
/// Every read and write is serialised, so two operations at once cannot each
/// read the list, change it and write over the other's change.
class TheEventsThisDeviceAskedFor {
  TheEventsThisDeviceAskedFor({FlutterSecureStorage? storage})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
              mOptions: MacOsOptions(useDataProtectionKeyChain: false),
            );

  final FlutterSecureStorage _storage;

  static const _name = 'events_asked_for';

  // One queue for every instance: two services over the same storage share
  // the same list.
  static Future<void> _tail = Future.value();

  static Future<T> _serialised<T>(Future<T> Function() op) {
    final result = _tail.then((_) => op());
    _tail = result.then((_) {}, onError: (_) {});
    return result;
  }

  /// The storage key for the active profile, to fix for a whole operation.
  Future<String> scope() => ProfileScope.key(_name);

  Future<List<Map<String, dynamic>>> _load(String key) async {
    final raw = await _storage.read(key: key);
    if (raw == null || raw.isEmpty) return [];
    return [for (final e in jsonDecode(raw) as List) Map<String, dynamic>.from(e as Map)];
  }

  Future<void> _save(String key, List<Map<String, dynamic>> entries) =>
      _storage.write(key: key, value: jsonEncode(entries));

  /// Records that this device is about to ask for an event of type [t] for
  /// [aid] (null for a founding, whose identifier does not exist yet), at
  /// sequence number [expectedSn], with what it asks for in [asked].
  Future<AskedEvent> asking(
      {required String t, String? aid, required int expectedSn, Map<String, dynamic> asked = const {}}) async {
    final key = await scope();
    return _serialised(() async {
      final entries = await _load(key);
      final id = '${DateTime.now().microsecondsSinceEpoch}-${entries.length}';
      entries.add({'id': id, 't': t, 'aid': aid, 'expected': expectedSn.toRadixString(16), 'asked': asked});
      await _save(key, entries);
      return AskedEvent._(id, key);
    });
  }

  /// Records which event the core added for [request].
  Future<void> added(AskedEvent request, {required String aid, required int sequenceNumber, required String digest}) =>
      _serialised(() async {
        final entries = await _load(request.storageKey);
        for (final e in entries) {
          if (e['id'] == request.id) {
            e['aid'] = aid;
            e['s'] = sequenceNumber.toRadixString(16);
            e['d'] = digest;
          }
        }
        await _save(request.storageKey, entries);
      });

  /// Forgets [request]: the core refused it, answered with something that is
  /// not it, failed to answer, or its event is now signed.
  Future<void> forget(AskedEvent request) => forgetId(request.storageKey, request.id);

  /// Forgets the entry [id] in the list at [storageKey].
  Future<void> forgetId(String storageKey, String id) => _serialised(() async {
        final entries = await _load(storageKey);
        entries.removeWhere((e) => e['id'] == id);
        await _save(storageKey, entries);
      });

  /// Every request still written down, for a test or a screen.
  Future<List<Map<String, dynamic>>> pending(String storageKey) => _serialised(() => _load(storageKey));

  /// Forgets every request [aid]'s log has settled: one whose event is signed,
  /// and one whose answer never arrived whose sequence number is now held by a
  /// signed event or passed by one.
  Future<void> forgetSettled(String storageKey, String aid, List<Map<String, dynamic>> events, List<bool> signed) =>
      _serialised(() async {
        final entries = await _load(storageKey);
        final done = {
          for (var i = 0; i < events.length; i++)
            if (signed[i]) '${events[i]['s']}|${events[i]['d']}',
        };
        var highestSigned = -1;
        for (var i = 0; i < events.length; i++) {
          final sn = int.tryParse('${events[i]['s']}', radix: 16);
          if (signed[i] && sn != null && sn > highestSigned) highestSigned = sn;
        }
        final before = entries.length;
        entries.removeWhere((e) {
          if (e['aid'] != null && e['aid'] != aid) return false;
          if (e['s'] != null) return e['aid'] == aid && done.contains('${e['s']}|${e['d']}');
          final expected = int.tryParse('${e['expected']}', radix: 16);
          return expected != null && expected <= highestSigned;
        });
        if (entries.length != before) await _save(storageKey, entries);
      });

  /// The id of the request that asked for [event] of [aid], or null if this
  /// device never asked for it. [commitmentTo] turns a key in qb64 into the
  /// digest a next-key commitment names.
  Future<String?> whichAskedFor(String storageKey, String aid, Map<String, dynamic> event,
          String Function(String key) commitmentTo) =>
      _serialised(() async {
        bool same(Object? a, Object? b) => jsonEncode(a) == jsonEncode(b);
        for (final e in await _load(storageKey)) {
          if (e['t'] != event['t'] || (e['aid'] != null && e['aid'] != aid)) continue;
          if (e['s'] != null) {
            if (e['s'] == event['s'] && e['d'] == event['d']) return e['id'] as String;
            continue;
          }
          // The answer never arrived: recognised by what was asked, and only at
          // the sequence number the event had to have.
          if (e['expected'] != event['s']) continue;
          final asked = Map<String, dynamic>.from(e['asked'] as Map);
          switch (event['t']) {
            case 'icp':
            case 'rot':
              // Recognised by the keys asked for: the key it names and the
              // next key it commits to first. Whether it is otherwise what
              // was asked is checked before it is signed.
              final n = event['n'];
              if (asked['key'] != null &&
                  same(event['k'], [asked['key']]) &&
                  n is List &&
                  n.isNotEmpty &&
                  n.first == commitmentTo(asked['next'] as String)) {
                return e['id'] as String;
              }
            case 'ixn':
              if (asked.containsKey('anchors') && same(event['a'], asked['anchors'])) return e['id'] as String;
          }
        }
        return null;
      });
}
