import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'profile_scope.dart';

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
/// (which keys, which anchors), and then the sequence number and digest the
/// core says it added. An event is recognised by its sequence number and
/// digest, or, where the answer never arrived, by what was asked.
class TheEventsThisDeviceAskedFor {
  TheEventsThisDeviceAskedFor({FlutterSecureStorage? storage})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
              mOptions: MacOsOptions(useDataProtectionKeyChain: false),
            );

  final FlutterSecureStorage _storage;

  static const _name = 'events_asked_for';

  Future<List<Map<String, dynamic>>> _load() async {
    final raw = await _storage.read(key: await ProfileScope.key(_name));
    if (raw == null || raw.isEmpty) return [];
    return [for (final e in jsonDecode(raw) as List) Map<String, dynamic>.from(e as Map)];
  }

  Future<void> _save(List<Map<String, dynamic>> entries) async {
    await _storage.write(key: await ProfileScope.key(_name), value: jsonEncode(entries));
  }

  /// Records that this device is about to ask for an event of type [t] for
  /// [aid] (null for a founding, whose identifier does not exist yet), with
  /// what it asks for in [asked]. Returns the entry's id.
  Future<String> asking({required String t, String? aid, Map<String, dynamic> asked = const {}}) async {
    final entries = await _load();
    final id = '${DateTime.now().microsecondsSinceEpoch}-${entries.length}';
    entries.add({'id': id, 't': t, 'aid': aid, 'asked': asked});
    await _save(entries);
    return id;
  }

  /// Records which event the core added for the request [id].
  Future<void> added(String id, {required String aid, required int sequenceNumber, required String digest}) async {
    final entries = await _load();
    for (final e in entries) {
      if (e['id'] == id) {
        e['aid'] = aid;
        e['s'] = sequenceNumber.toRadixString(16);
        e['d'] = digest;
      }
    }
    await _save(entries);
  }

  /// Forgets the request [id]: the core refused it, or its event is signed.
  Future<void> forget(String id) async {
    final entries = await _load();
    entries.removeWhere((e) => e['id'] == id);
    await _save(entries);
  }

  /// Forgets every request whose event [aid]'s log now shows signed: there is
  /// nothing left for this device to finish for it.
  Future<void> forgetSigned(String aid, Iterable<Map<String, dynamic>> signedEvents) async {
    final entries = await _load();
    final done = {for (final e in signedEvents) '${e['s']}|${e['d']}'};
    final before = entries.length;
    entries.removeWhere((e) => e['aid'] == aid && e['s'] != null && done.contains('${e['s']}|${e['d']}'));
    if (entries.length != before) await _save(entries);
  }

  /// The id of the request that asked for [event] of [aid], or null if this
  /// device never asked for it. [commitmentTo] turns a key in qb64 into the
  /// digest a next-key commitment names.
  Future<String?> whichAskedFor(String aid, Map<String, dynamic> event,
      String Function(String key) commitmentTo) async {
    for (final e in await _load()) {
      if (e['t'] != event['t'] || (e['aid'] != null && e['aid'] != aid)) continue;
      if (e['s'] != null) {
        if (e['s'] == event['s'] && e['d'] == event['d']) return e['id'] as String;
        continue;
      }
      // The answer never arrived: recognised by what was asked.
      final asked = Map<String, dynamic>.from(e['asked'] as Map);
      bool same(Object? a, Object? b) => jsonEncode(a) == jsonEncode(b);
      switch (event['t']) {
        case 'icp':
        case 'rot':
          if (asked['key'] != null &&
              same(event['k'], [asked['key']]) &&
              same(event['n'], [commitmentTo(asked['next'] as String)])) {
            return e['id'] as String;
          }
        case 'ixn':
          if (asked.containsKey('anchors') && same(event['a'], asked['anchors'])) return e['id'] as String;
      }
    }
    return null;
  }
}
