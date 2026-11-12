/// The software this app is willing to adopt a sealed machine for.
///
/// A machine that proves what it launched has said what it is. It has not said
/// whether the owner accepts it, and those are different questions — an agent
/// with no policy refuses every sealed machine on purpose, because a missing
/// policy read as "accept anything" would make every other check decorative.
///
/// The answer is a signed list, published, with the publisher's key pinned in
/// the app (`MEASUREMENT_PUBLISHER_KEY_HEX` and `_ID` at build time), so that
/// everybody receives the same list and serving one person a different one
/// requires the key and is detectable. The list comes from
/// `MEASUREMENT_LIST_URL` or, failing that, the app's bundled
/// `assets/measurement_list.json`; both are signed, so neither is trusted for
/// where it came from. The format and its checks are the Go core's
/// (`identity-agent-core/measurementlist`); `measurement_list.dart` is tested
/// against that package's own vectors.
///
/// `ACCEPTED_MEASUREMENTS` is the bootstrap copy. It is used only while no list
/// has ever been accepted on this device. After one has, it is never used
/// again: it is the oldest policy there is, and falling back to it would let a
/// damaged, missing, older or expired list force that policy and undo the
/// rollback protection (the same rule as the core's measurementPolicy).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/services.dart' show rootBundle;
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

import 'measurement_list.dart';

/// Measurements compiled into this build, newline or comma separated.
const String _fromBuild = String.fromEnvironment('ACCEPTED_MEASUREMENTS');

/// The publisher key pinned in this build. Empty verifies no list. Not read
/// from anywhere at run time: whoever starts the app is not who decides whom
/// the owner trusts.
const String _publisherKeyHex = String.fromEnvironment('MEASUREMENT_PUBLISHER_KEY_HEX');
const String _publisherKeyId = String.fromEnvironment('MEASUREMENT_PUBLISHER_KEY_ID');
const String _listUrl = String.fromEnvironment('MEASUREMENT_LIST_URL');

const String _floorKey = 'measurement_list_floor';
const String bundledMeasurementListAsset = 'assets/measurement_list.json';

/// The bootstrap, as lowercase hex, empty when nothing was set. Empty is a real
/// answer and the safe one: it adopts nothing rather than anything.
List<String> bootstrapMeasurements([String raw = _fromBuild]) {
  raw = raw.trim();
  if (raw.isEmpty) return const [];
  return raw
      .split(RegExp(r'[\s,]+'))
      .map((m) => m.trim().toLowerCase())
      .where((m) => RegExp(r'^[0-9a-f]{96}$').hasMatch(m))
      .toList(growable: false);
}

/// Where the highest accepted sequence is kept, as "<sequence> <digest>".
abstract class MeasurementFloorStore {
  Future<String?> read();
  Future<void> write(String record);
}

class _PrefsFloorStore implements MeasurementFloorStore {
  @override
  Future<String?> read() async => (await SharedPreferences.getInstance()).getString(_floorKey);
  @override
  Future<void> write(String record) async =>
      (await SharedPreferences.getInstance()).setString(_floorKey, record);
}

/// Where lists come from, in order. Each is tried until one verifies.
typedef MeasurementListSource = Future<Uint8List?> Function();

Future<Uint8List?> _fromUrl() async {
  if (_listUrl.isEmpty) return null;
  final r = await http.get(Uri.parse(_listUrl)).timeout(const Duration(seconds: 10));
  return r.statusCode == 200 ? r.bodyBytes : null;
}

Future<Uint8List?> _fromAsset() async =>
    (await rootBundle.load(bundledMeasurementListAsset)).buffer.asUint8List();

/// What this app will adopt a sealed machine of [kind] for, as lowercase hex.
///
/// Empty means "name nothing on the request", after which the agent's own
/// policy stands (and an agent with none refuses); never "accept anything".
///
/// Every parameter but [kind] is a seam for tests; the defaults are the build's
/// pinned key, URL and bundled list, and this device's preferences.
Future<List<String>> acceptedMeasurements({
  required String kind,
  DateTime? now,
  String publisherKeyHex = _publisherKeyHex,
  String publisherKeyId = _publisherKeyId,
  List<MeasurementListSource>? sources,
  MeasurementFloorStore? floorStore,
  List<String>? bootstrap,
}) async {
  final at = (now ?? DateTime.now()).toUtc();
  final store = floorStore ?? _PrefsFloorStore();
  final record = (await store.read() ?? '').trim().split(RegExp(r'\s+'));
  final floor = int.tryParse(record.first) ?? 0;
  final seen = record.length > 1 ? record[1] : '';
  final everAccepted = floor > 0;

  for (final source in sources ?? const [_fromUrl, _fromAsset]) {
    try {
      final raw = await source();
      if (raw == null) continue;
      final list = verifyMeasurementList(raw,
          publisherKeyHex: publisherKeyHex,
          publisherKeyId: publisherKeyId,
          now: at,
          minSequence: floor,
          seenDigest: seen);
      if (list.sequence > floor || seen.isEmpty) {
        // Not recorded means a later rollback would not be caught, so a list
        // is not used on the strength of a floor that did not stick.
        await store.write('${list.sequence} ${list.digest}');
      }
      return list.measurementsAt(kind, at);
    } catch (_) {
      // This source did not give a usable list; try the next.
    }
  }
  return everAccepted ? const [] : (bootstrap ?? bootstrapMeasurements());
}
