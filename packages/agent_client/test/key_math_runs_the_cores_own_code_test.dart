import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:test/test.dart';

/// A signature check that accepts, for running a locally built core in a test.
/// What it stands in for is the platform's own check, which a locally built
/// binary would fail; the hash check is still made.
class _SignedByUs implements BinarySignature {
  @override
  Future<void> requireSameSigner(String binary, String app) async {}
}

class _SignedBySomebodyElse implements BinarySignature {
  @override
  Future<void> requireSameSigner(String binary, String app) async =>
      throw KeyMathBinaryRefused(
          'it is not signed by the team that signed this app');
}

/// The hardened indexes of a path written m/44'/0'/…
List<int> _hardened(String path) => [
      for (final part in path.split('/').skip(1))
        0x80000000 + int.parse(part.replaceAll("'", '')),
    ];

Uint8List _hexBytes(String h) => Uint8List.fromList([
      for (var i = 0; i < h.length; i += 2)
        int.parse(h.substring(i, i + 2), radix: 16)
    ]);

void main() {
  late String core;
  late String coreHash;

  setUpAll(() async {
    final dir = await Directory.systemTemp.createTemp('keymath-core');
    core = '${dir.path}/identity-agent-core${Platform.isWindows ? '.exe' : ''}';
    final built = await Process.run('go', ['build', '-o', core, '.'],
        workingDirectory: '../../identity-agent-core');
    if (built.exitCode != 0) {
      fail('the core could not be built for this test: ${built.stderr}');
    }
    coreHash = crypto.sha256.convert(await File(core).readAsBytes()).toString();
  });

  final vectors = jsonDecode(
      File('../../identity-agent-core/backup/identity-key-vectors.json')
          .readAsStringSync()) as Map;
  final phrase = (vectors['phrases'] as List).first as Map;

  test('the shared key vectors come out of the core through KeyMath', () async {
    final km = CommandKeyMath(
        binaryPath: core, expectedSha256: coreHash, signature: _SignedByUs());
    for (final pq in phrase['post_quantum'] as List) {
      final got = await km.postQuantumNext(_hexBytes(pq['seed_hex'] as String));
      expect(got.verkey, pq['verkey_qb64']);
      if (pq['digest'] != null) expect(got.digest, pq['digest']);
    }
    final bip39 = _hexBytes(phrase['bip39_seed_hex'] as String);
    for (final m in phrase['messaging'] as List) {
      final seed =
          KeyManager.slip10Ed25519(bip39, _hardened(m['path'] as String));
      final got = await km.messagingKeySet(seed);
      expect(jsonEncode(got), jsonEncode(m['anchor']));
    }
    final founding =
        (phrase['signature_forms'] as Map)['founding_raw'] as String;
    final parsed = await km.parseEvent(utf8.encode(founding));
    expect(parsed.t, 'icp');
    expect(parsed.s, 0);
    expect(parsed.names.take(4), ['v', 't', 'd', 'i']);
    expect((parsed['n'] as List).length, 2);
  });

  test('a core binary that is not the one built with the app is never run',
      () async {
    final tampered = File('${File(core).parent.path}/tampered');
    await tampered.writeAsBytes([...await File(core).readAsBytes(), 0]);
    if (!Platform.isWindows) await Process.run('chmod', ['+x', tampered.path]);
    final km = CommandKeyMath(
        binaryPath: tampered.path,
        expectedSha256: coreHash,
        signature: _SignedByUs());
    await expectLater(
        km.parseEvent(utf8.encode('{}')), throwsA(isA<KeyMathBinaryRefused>()));
    final none = CommandKeyMath(
        binaryPath: core, expectedSha256: '', signature: _SignedByUs());
    await expectLater(none.parseEvent(utf8.encode('{}')),
        throwsA(isA<KeyMathBinaryRefused>()));
  });

  test('a core binary signed by somebody else is never run', () async {
    final km = CommandKeyMath(
        binaryPath: core,
        expectedSha256: coreHash,
        signature: _SignedBySomebodyElse());
    await expectLater(
        km.parseEvent(utf8.encode('{}')), throwsA(isA<KeyMathBinaryRefused>()));
  });

  test('an unsigned locally built binary fails the platform signature check',
      () async {
    if (!Platform.isMacOS && !Platform.isWindows) return;
    final km = CommandKeyMath(binaryPath: core, expectedSha256: coreHash);
    await expectLater(
        km.parseEvent(utf8.encode('{}')), throwsA(isA<KeyMathBinaryRefused>()));
  });

  test('a refusal says what is wrong with the request and nothing more',
      () async {
    final km = CommandKeyMath(
        binaryPath: core, expectedSha256: coreHash, signature: _SignedByUs());
    final seed = 'ff' * 31;
    try {
      await km.run('pq_next', {'seed_hex': seed});
      fail('a short seed was taken');
    } on KeyMathRefused catch (e) {
      expect(e.reason, isNot(contains(seed)));
    }
  });

  test('BridgeKeyMath carries a phone bridge\'s answers and refusals',
      () async {
    final km = BridgeKeyMath((op, req) async {
      if (op == 'next_key_digest') return '{"digest":"Eabc"}';
      throw Exception('unknown keymath operation');
    });
    expect(await km.nextKeyDigest('Dkey'), 'Eabc');
    await expectLater(km.run('nope', {}), throwsA(isA<KeyMathRefused>()));
  });
}
