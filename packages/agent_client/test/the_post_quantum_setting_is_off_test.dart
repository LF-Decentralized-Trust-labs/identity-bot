import 'dart:io';
import 'dart:typed_data';

import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/the_event_this_device_expects.dart';
import 'package:agent_client/services/the_key_events_this_device_makes.dart';
import 'package:agent_client/services/the_witnesses_of_this_devices_events.dart';
import 'package:http/http.dart' as http;
import 'package:test/test.dart';

/// Reaching the network or the key arithmetic would be a failure here: with
/// the setting off, a stage-two event is refused before either is asked.
class _ReachesNothing extends http.BaseClient implements KeyMath {
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) =>
      throw StateError('a request was made: ${request.url}');
  @override
  Future<Map<String, dynamic>> run(String op, Map<String, dynamic> request) =>
      throw StateError('keymath was asked for $op');
}

void main() {
  test('the setting that allows a post-quantum key to be revealed is off', () {
    expect(PostQuantumCodes.assigned, isFalse);
  });

  test(
      'with it off, a stage-two rotation and a dual-signed interaction are refused before anything is asked',
      () async {
    final nothing = _ReachesNothing();
    // The key state this device reads says the identity is at stage two: `k`
    // holds the classical key and a post-quantum one.
    final makes =
        TheKeyEventsThisDeviceMakes(nothing, 'http://127.0.0.1:1', nothing,
            readTheKeyState: (_) async => (
                  tip: (sn: 1, digest: 'EPrior'),
                  generation: 1,
                  witnesses: WitnessSet.none,
                  keys: ['DClassical', '2AAEPostQuantum']
                ));
    final seed = Uint8List(64);
    await expectLater(
        makes.rotateToStageTwo(seed,
            aid: 'EAid',
            generation: 0,
            afterSn: 0,
            afterDigest: 'EPrior',
            reCommitWitnessed: true),
        throwsA(isA<PostQuantumNotYet>()));
    await expectLater(
        makes.interact(seed,
            aid: 'EAid',
            generation: 1,
            afterSn: 1,
            afterDigest: 'EPrior',
            anchors: const []),
        throwsA(isA<PostQuantumNotYet>()));
    await expectLater(
        makes.rotate(seed,
            aid: 'EAid', generation: 1, afterSn: 1, afterDigest: 'EPrior'),
        throwsA(isA<PostQuantumNotYet>()));
  });

  test(
      'the setting is for tests only, and refuses to turn on in a release build',
      () {
    final src = File('lib/services/the_event_this_device_expects.dart')
        .readAsStringSync();
    expect(src,
        contains('@visibleForTesting\n  static void useAssignedCodesInATest'));
    // The default is whether this is a release build. A test never runs in
    // one, so the default cannot be seen to refuse here; it is pinned in the
    // source, where changing it to `false` would let a release build turn the
    // setting on.
    expect(src, contains('{bool inARelease = kReleaseMode}'));
    // The decision itself: told it is a release build, it refuses and changes
    // nothing; told it is not, it turns on and off.
    expect(
        () => PostQuantumCodes.useAssignedCodesInATest(true, inARelease: true),
        throwsStateError);
    expect(PostQuantumCodes.assigned, isFalse);
    PostQuantumCodes.useAssignedCodesInATest(false, inARelease: true);
    PostQuantumCodes.useAssignedCodesInATest(true, inARelease: false);
    expect(PostQuantumCodes.assigned, isTrue);
    PostQuantumCodes.useAssignedCodesInATest(false);
    expect(PostQuantumCodes.assigned, isFalse);
  });

  test('nothing the app ships turns the setting on', () {
    final users = [
      for (final f in Directory('lib').listSync(recursive: true))
        if (f is File &&
            f.path.endsWith('.dart') &&
            f.readAsStringSync().contains('useAssignedCodesInATest'))
          f.path
    ];
    expect(users, ['lib/services/the_event_this_device_expects.dart'],
        reason: 'only its definition may name it under lib');
  });
}
