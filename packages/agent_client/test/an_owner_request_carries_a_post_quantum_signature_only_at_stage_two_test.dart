import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/owner_signature.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/owner_signing_client.dart';
import 'package:agent_client/services/the_event_this_device_expects.dart';
import 'package:agent_client/services/the_key_events_this_device_makes.dart';
import 'package:agent_client/services/the_key_state_this_device_reads.dart';
import 'package:agent_client/services/the_witnesses_of_this_devices_events.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:http/http.dart' as http;
import 'package:test/test.dart';

/// What the owner-signing client sends to its agent, by the stage the identity
/// is at, without a core: the key arithmetic and the key state are given.
class _Recorder extends http.BaseClient {
  http.BaseRequest? last;
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    last = request;
    return http.StreamedResponse(const Stream.empty(), 200);
  }
}

/// Key arithmetic that answers as a post-quantum signature does, with no core.
class _KeyMath implements KeyMath {
  _KeyMath(this.pqVerkey);
  final String pqVerkey;
  @override
  Future<Map<String, dynamic>> run(
      String op, Map<String, dynamic> request) async {
    switch (op) {
      case 'pq_next':
        return {'verkey': pqVerkey, 'digest': 'D'};
      case 'sign_mldsa65':
        return {
          'sig_b64': base64Encode([1, 2, 3])
        };
      case 'index_mldsa65_sig':
        return {'sig_qb64': 'A-post-quantum-signature'};
    }
    throw KeyMathRefused(op, 'not asked for here');
  }
}

/// A reader that says the key state is [keys] at [generation].
class _Reads extends TheKeyStateThisDeviceReads {
  _Reads(KeyMath km, this.keys, this.generation) : super(http.Client(), km, '');
  final List<String> keys;
  final int generation;
  @override
  Future<VerifiedKeyState> read(Uint8List seed) async => VerifiedKeyState(
      aid: 'EAid',
      establishment: (sn: 1, digest: 'EEst'),
      keyInForce: keys.first,
      keysInForce: keys,
      generation: generation,
      tip: (sn: 1, digest: 'EEst'),
      witnesses: WitnessSet.none,
      fromItsOwnRecord: true,
      corroborated: true);
}

void main() {
  const agent = 'https://my-agent.example.org';
  final phrase = Bip39.mnemonicToSeed(
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
          .split(' '));

  setUp(() => PostQuantumCodes.useAssignedCodesInATest(true));
  tearDown(() => PostQuantumCodes.useAssignedCodesInATest(false));

  Future<http.BaseRequest> sentBy(List<String> keys, int generation) async {
    final km = _KeyMath('2AAEpq');
    final owner = ownerKeyFromThePhrase(() async => ['unused'],
        (_) => Uint8List.fromList(phrase), _Reads(km, keys, generation),
        keyMath: km);
    final recorder = _Recorder();
    await OwnerSigningClient(
            agentOrigin: agent,
            agentAid: 'EAgent',
            ownerKey: owner.ownerKey,
            postQuantumSeed: owner.postQuantumSeed,
            keyMath: km,
            inner: recorder)
        .get(Uri.parse('$agent/api/identity'));
    return recorder.last!;
  }

  test('an owner at stage one sends no post-quantum signature', () async {
    final sent = await sentBy([KeyManager.publicKeyAt(phrase, 1)], 1);
    expect(sent.headers, contains(OwnerSignature.sigHeader));
    expect(
        sent.headers.containsKey(OwnerSignature.postQuantumSigHeader), isFalse);
  });

  test('an owner at stage two sends the post-quantum signature as well',
      () async {
    final sent = await sentBy([KeyManager.publicKeyAt(phrase, 1), '2AAEpq'], 1);
    // The fake's post-quantum key is derived from nothing, so the seed check
    // against `k` is what passes here: the key in k is the one it derives.
    expect(sent.headers[OwnerSignature.postQuantumSigHeader],
        'A-post-quantum-signature');
  });

  test('the post-quantum seed an owner request signed with is zeroed',
      () async {
    final seed = Uint8List.fromList(List.filled(32, 7));
    final km = _KeyMath('2AAEpq');
    final recorder = _Recorder();
    await OwnerSigningClient(
            agentOrigin: agent,
            agentAid: 'EAgent',
            ownerSeed: () async => Uint8List.fromList(List.filled(32, 1)),
            postQuantumSeed: () async => seed,
            keyMath: km,
            inner: recorder)
        .get(Uri.parse('$agent/api/identity'));
    expect(
        recorder.last!.headers, contains(OwnerSignature.postQuantumSigHeader),
        reason: 'the seed was not used');
    expect(seed.every((b) => b == 0), isTrue,
        reason: 'the post-quantum seed was left in memory');
  });

  group('the stage check, made in one place for events and requests', () {
    test('a post-quantum seed that is not the one in k is zeroed, not kept',
        () async {
      final held = Uint8List.fromList(List.filled(32, 9));
      await expectLater(
          thePostQuantumSeedInForce(_KeyMath('2AAEpq'), Uint8List(64), 'EAid',
              1, ['Dclassical', '2AAEother'],
              derive: (_, __) => held),
          throwsA(isA<ThePostQuantumKeyInForceIsNotThisPhrases>()));
      expect(held.every((b) => b == 0), isTrue,
          reason: 'the derived seed was left in memory after the check failed');
    });

    test('one that is the key in k is handed over whole', () async {
      final held = Uint8List.fromList(List.filled(32, 9));
      final got = await thePostQuantumSeedInForce(_KeyMath('2AAEpq'),
          Uint8List(64), 'EAid', 1, ['Dclassical', '2AAEpq'], derive: (_, g) {
        expect(g, 0, reason: 'the post-quantum key of generation - 1');
        return held;
      });
      expect(got, same(held));
      expect(held.every((b) => b == 9), isTrue);
    });

    test(
        'stage one has none, and a stage this phrase does not sign for is refused',
        () async {
      final km = _KeyMath('2AAEpq');
      expect(
          await thePostQuantumSeedInForce(km, Uint8List(64), 'EAid', 0, ['Dc']),
          isNull);
      for (final (generation, keys) in [
        (0, ['Dc', '2AAEpq']),
        (1, ['Dc', '2AAEpq', 'Dd'])
      ]) {
        await expectLater(
            thePostQuantumSeedInForce(
                km, Uint8List(64), 'EAid', generation, keys),
            throwsA(isA<ThePostQuantumKeyInForceIsNotThisPhrases>()),
            reason: '$keys at generation $generation');
      }
    });
  });
}
