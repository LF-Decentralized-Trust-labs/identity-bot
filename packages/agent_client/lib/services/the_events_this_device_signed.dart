import 'dart:async';
import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'profile_scope.dart';

/// An event this device has reserved a place for: the identity, its place and
/// prior, the digest and the exact bytes, and the signatures once made.
class Reservation {
  Reservation._(this.storageKey, this.entry);
  final String storageKey;
  final Map<String, dynamic> entry;

  String get aid => entry['aid'] as String;
  int get sn => entry['s'] as int;
  String get prior => entry['p'] as String? ?? '';
  String get digest => entry['d'] as String;
  String get bytesB64 => entry['bytes'] as String;
  List<String> get signatures =>
      [for (final s in (entry['sigs'] as List? ?? const [])) '$s'];
  bool get signed => signatures.isNotEmpty;

  /// The event's type (`icp`, `rot`, `ixn`), or null for a reservation made
  /// before types were recorded.
  String? get t => entry['t'] as String?;

  /// For an establishment event, the key it reveals and that key's
  /// generation of the phrase that signs it.
  String? get key => entry['key'] as String?;
  int? get generation => (entry['g'] as num?)?.toInt();

  /// Whether the core acknowledged adding the event.
  bool get recorded => entry['recorded'] == true;

  /// Whether enough of the identity's witnesses receipted the event, each
  /// receipt checked by this device. A reservation ends only when both the
  /// core and the witnesses have the event, so until then it can still be
  /// sent to either, or to a new core.
  bool get witnessed => entry['witnessed'] == true;

  /// The code the core refused the event with, for good, or null. A refused
  /// event still holds its place: nothing else is signed there until the
  /// person lets it go ([TheEventsThisDeviceSigned.letGo]).
  String? get refusedWith => entry['refused'] as String?;
}

/// A different event at a place this device already reserved for one.
class PlaceAlreadyReserved implements Exception {
  PlaceAlreadyReserved(this.aid, this.sn, this.held, this.asked);
  final String aid;
  final int sn;
  final String held;
  final String asked;
  @override
  String toString() =>
      'this device has already reserved sequence number $sn of $aid for '
      '$held, so it will not sign $asked there';
}

/// The events of an identity's key log this device signs, each reserved before
/// it is signed (ADR-061 section 5).
///
/// Prepare and commit are two calls, and the signing happens between them, so
/// a crash or a lost answer can leave a signed event that the core never
/// added. What must never follow is a second, different event signed at the
/// same place: two signed events at one place are duplicity, whoever caused
/// it. So before signing, the identity, place, prior and digest are written
/// down with the exact bytes, and a second digest at a reserved place is
/// refused. After a crash only those bytes can be signed there, and an event
/// already signed is committed again before anything new is prepared.
///
/// A reservation ends when its event is committed, or when a recovery rotation
/// this device signs supersedes it ([supersededBy]), which marks it dead: its
/// place is the rotation's now.
///
/// Every read and write is serialised, so two operations at once cannot each
/// read the list, change it and write over the other's change.
class TheEventsThisDeviceSigned {
  TheEventsThisDeviceSigned({FlutterSecureStorage? storage})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
              mOptions: MacOsOptions(useDataProtectionKeyChain: false),
            );

  final FlutterSecureStorage _storage;

  static const _name = 'events_signed';

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
    return [
      for (final e in jsonDecode(raw) as List)
        Map<String, dynamic>.from(e as Map)
    ];
  }

  Future<void> _save(String key, List<Map<String, dynamic>> entries) =>
      _storage.write(key: key, value: jsonEncode(entries));

  /// Reserves sequence number [sn] of [aid] for the event whose digest is
  /// [digest], prior [prior] and bytes [bytesB64]. Reserving the same event
  /// again returns its reservation, with any signatures already made. Throws
  /// [PlaceAlreadyReserved] where the place is reserved for another event.
  Future<Reservation> reserve(
      {required String aid,
      required int sn,
      required String prior,
      required String digest,
      required String bytesB64,
      String? t,
      String? reveals,
      int? generation}) async {
    final key = await scope();
    return _serialised(() async {
      final entries = await _load(key);
      for (final e in entries) {
        if (e['aid'] != aid || e['s'] != sn || e['dead'] == true) continue;
        if (e['d'] == digest && e['bytes'] == bytesB64)
          return Reservation._(key, e);
        throw PlaceAlreadyReserved(aid, sn, '${e['d']}', digest);
      }
      final e = <String, dynamic>{
        'aid': aid,
        's': sn,
        'p': prior,
        'd': digest,
        'bytes': bytesB64,
        if (t != null) 't': t,
        if (reveals != null) 'key': reveals,
        if (generation != null) 'g': generation
      };
      entries.add(e);
      await _save(key, entries);
      return Reservation._(key, e);
    });
  }

  /// Records the signatures made over [r]'s bytes, before they are sent.
  Future<Reservation> signedWith(Reservation r, List<String> signatures) =>
      _serialised(() async {
        final entries = await _load(r.storageKey);
        for (final e in entries) {
          if (_same(e, r.entry)) {
            e['sigs'] = signatures;
            await _save(r.storageKey, entries);
            return Reservation._(r.storageKey, e);
          }
        }
        throw StateError(
            'the reservation of sequence number ${r.sn} of ${r.aid} is gone');
      });

  /// Ends [r]: its event is in the identity's log, and witnessed as far as
  /// this device needs it to be.
  Future<void> committed(Reservation r) => _serialised(() async {
        final entries = await _load(r.storageKey);
        entries.removeWhere((e) => _same(e, r.entry));
        await _save(r.storageKey, entries);
      });

  /// Marks [r] added by the core.
  Future<Reservation> recorded(Reservation r) => _mark(r, 'recorded', true);

  /// Marks [r] receipted by enough of its witnesses.
  Future<Reservation> witnessed(Reservation r) => _mark(r, 'witnessed', true);

  /// Marks [r] refused by the core for good, with [code]; null clears it, for
  /// an event the witnesses turn out to hold.
  Future<Reservation> refused(Reservation r, String? code) =>
      _mark(r, 'refused', code);

  /// Marks [r] dead: the person let it go after its place was checked with
  /// the witnesses, or the witnesses hold another event there. Nothing of it
  /// is committed again, and its place may be signed for again.
  Future<Reservation> letGo(Reservation r) => _mark(r, 'dead', true);

  Future<Reservation> _mark(Reservation r, String field, Object? value) =>
      _serialised(() async {
        final entries = await _load(r.storageKey);
        for (final e in entries) {
          if (_same(e, r.entry)) {
            e[field] = value;
            await _save(r.storageKey, entries);
            return Reservation._(r.storageKey, e);
          }
        }
        throw StateError(
            'the reservation of sequence number ${r.sn} of ${r.aid} is gone');
      });

  /// Marks dead every reservation of an interaction of [aid] at or after
  /// [sn]: a recovery rotation at [sn] this device is about to sign
  /// supersedes them, so none of them may be signed or committed again. A
  /// reservation of anything else, or of an event whose type was not
  /// recorded, is left: a rotation does not supersede one, and the new
  /// rotation's own reservation will be refused at its place instead.
  Future<void> supersededBy(String aid, int sn) async {
    final key = await scope();
    await _serialised(() async {
      final entries = await _load(key);
      for (final e in entries) {
        if (e['aid'] == aid &&
            (e['s'] as int) >= sn &&
            e['t'] == 'ixn' &&
            e['dead'] != true) e['dead'] = true;
      }
      await _save(key, entries);
    });
  }

  /// The reservations of [aid] still to finish, in place order: signed ones
  /// first, since those are committed again before anything new is prepared.
  Future<List<Reservation>> unfinished(String aid) async {
    final key = await scope();
    return _serialised(() async {
      final live = [
        for (final e in await _load(key))
          if (e['aid'] == aid && e['dead'] != true) Reservation._(key, e),
      ];
      live.sort((a, b) {
        if (a.signed != b.signed) return a.signed ? -1 : 1;
        return a.sn.compareTo(b.sn);
      });
      return live;
    });
  }

  /// Whether this device may sign the event [digest] at [sn] of [aid]: yes
  /// unless the place is reserved for another event.
  Future<bool> maySign(String aid, int sn, String digest) async {
    final key = await scope();
    return _serialised(() async {
      for (final e in await _load(key)) {
        if (e['aid'] == aid && e['s'] == sn && e['dead'] != true)
          return e['d'] == digest;
      }
      return true;
    });
  }

  static bool _same(Map<String, dynamic> a, Map<String, dynamic> b) =>
      a['aid'] == b['aid'] &&
      a['s'] == b['s'] &&
      a['d'] == b['d'] &&
      a['dead'] == b['dead'];
}
