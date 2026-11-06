import 'dart:typed_data';

import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/the_key_events_this_device_makes.dart';
import 'package:agent_client/services/the_witnesses_of_this_devices_events.dart';
import 'package:http/http.dart' as http;
import 'package:test/test.dart';

/// The stage is read from the key state, by either of the two readers a device
/// can be given, and a caller whose generation is out of date is told the log
/// has moved by both ([TheLogKeepsMoving]), not by one and a stage error from
/// the other.
class _NeverAsked implements KeyMath {
  @override
  Future<Map<String, dynamic>> run(String op, Map<String, dynamic> request) =>
      throw StateError('the key arithmetic was asked for $op');
}

void main() {
  final seed = Uint8List(64);
  const aid = 'EAid';
  // The log is at generation 2 with two keys in k, and the caller says 1.
  KeyStateNow state() => (
        tip: (sn: 3, digest: 'ETip'),
        generation: 2,
        witnesses: WitnessSet.none,
        keys: ['DClassical', '2AAEPostQuantum']
      );

  Future<void> interactAtGenerationOne(TheKeyEventsThisDeviceMakes makes) =>
      makes.interact(seed,
          aid: aid,
          generation: 1,
          afterSn: 3,
          afterDigest: 'ETip',
          anchors: const []);

  test('a stale caller is told the log keeps moving by readTheKeyState',
      () async {
    final makes = TheKeyEventsThisDeviceMakes(
        http.Client(), 'http://unused', _NeverAsked(),
        readTheKeyState: (_) async => state());
    await expectLater(
        interactAtGenerationOne(makes), throwsA(isA<TheLogKeepsMoving>()));
  });

  test('a stale caller is told the log keeps moving by readTheKeysInForce',
      () async {
    final makes = TheKeyEventsThisDeviceMakes(
        http.Client(), 'http://unused', _NeverAsked(),
        readTheKeysInForce: (_) async => state());
    await expectLater(
        interactAtGenerationOne(makes), throwsA(isA<TheLogKeepsMoving>()));
  });
}
