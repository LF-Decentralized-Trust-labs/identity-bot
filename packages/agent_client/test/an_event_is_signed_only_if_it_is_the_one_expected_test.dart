import 'dart:convert';
import 'dart:io';

import 'package:agent_client/crypto/owner_signature.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/the_event_this_device_expects.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:test/test.dart';

class _SignedByUs implements BinarySignature {
  @override
  Future<void> requireSameSigner(String binary, String app) async {}
}

/// A KERI 1.0 JSON event with its digest (and, for a founding, identifier)
/// filled in, from fields in order. The core's parser then confirms the digest,
/// so an event made here that the parser accepts is a real event.
List<int> saidified(Map<String, Object?> fields) {
  const placeholder = '############################################';
  final m = <String, Object?>{'v': 'KERI10JSON000000_', ...fields};
  m['d'] = placeholder;
  if (m['t'] == 'icp') m['i'] = placeholder;
  final size = utf8.encode(jsonEncode(m)).length;
  m['v'] = 'KERI10JSON${size.toRadixString(16).padLeft(6, '0')}_';
  final said = OwnerSignature.blake3QB64(utf8.encode(jsonEncode(m)));
  m['d'] = said;
  if (m['t'] == 'icp') m['i'] = said;
  return utf8.encode(jsonEncode(m));
}

const key = 'DC9_fhFpkQz7Q23jYk4JbvAuUPriHlz3N_gTrmghEh51';
const next = [
  'EF9uapKiykyI31D_3yA-7FVb9Z0GYq9v7TAvuXuNjqpq',
  'EIHUKeehZjOIIbaKdnSH0FFe5zxYVpy4CVPj-Itm32EE'
];
const anchor = {'ia': 'IA-HYBRID-1', 'ka': [], 'sa': []};

Map<String, Object?> founding(
    {Map<String, Object?> change = const {},
    String? drop,
    Map<String, Object?> add = const {}}) {
  final f = <String, Object?>{
    't': 'icp',
    'd': '',
    'i': '',
    's': '0',
    'kt': '1',
    'k': [key],
    'nt': '1',
    'n': next,
    'bt': '0',
    'b': [],
    'c': [],
    'a': [anchor],
  };
  f.addAll(change);
  if (drop != null) f.remove(drop);
  f.addAll(add);
  return f;
}

void main() {
  late KeyMath km;

  setUpAll(() async {
    final dir = await Directory.systemTemp.createTemp('expects-core');
    final core =
        '${dir.path}/identity-agent-core${Platform.isWindows ? '.exe' : ''}';
    final built = await Process.run('go', ['build', '-o', core, '.'],
        workingDirectory: '../../identity-agent-core');
    if (built.exitCode != 0)
      fail('the core could not be built for this test: ${built.stderr}');
    km = CommandKeyMath(
        binaryPath: core,
        expectedSha256:
            crypto.sha256.convert(await File(core).readAsBytes()).toString(),
        signature: _SignedByUs());
  });

  final expectedFounding =
      ExpectedEvent.founding(keys: [key], next: next, anchors: [anchor]);

  test('the founding this device expects is signed', () async {
    final ev = await expectedFounding.requireIn(km, saidified(founding()));
    expect(ev.t, 'icp');
  });

  final refused = <String, Map<String, Object?>>{
    'another key': founding(change: {
      'k': ['DAnotherKeyAnotherKeyAnotherKeyAnotherKey12']
    }),
    'a third next-key commitment': founding(change: {
      'n': [...next, 'EThirdDigestThirdDigestThirdDigestThirdDig1']
    }),
    'a post-quantum digest from another seed': founding(change: {
      'n': [next[0], 'EAnotherDigestAnotherDigestAnotherDigest123']
    }),
    'a configuration trait': founding(change: {
      'c': ['EO']
    }),
    'a witness nobody asked for': founding(change: {
      'b': ['BKRaC6UsijUY1FRjExoAMc8WOHBDIfIKYnOlxWH8eOe8'],
      'bt': '1'
    }),
    'another anchor': founding(change: {
      'a': [
        anchor,
        {'i': 'Ex', 's': '0', 'd': 'Ex'}
      ]
    }),
    'a different threshold': founding(change: {'nt': '2'}),
  };
  refused.forEach((why, fields) {
    test('a founding with $why is not signed', () async {
      await expectLater(expectedFounding.requireIn(km, saidified(fields)),
          throwsA(isA<NotTheEventExpected>()));
    });
  });

  test('bytes the parser refuses are not signed', () async {
    final bytes = saidified(founding());
    final tampered =
        utf8.encode(utf8.decode(bytes).replaceFirst('"kt":"1"', '"kt":"2"'));
    await expectLater(expectedFounding.requireIn(km, tampered),
        throwsA(isA<NotTheEventExpected>()));
  });

  const aid = 'EAidAidAidAidAidAidAidAidAidAidAidAidAidAid1';
  const prior = 'EPriorPriorPriorPriorPriorPriorPriorPriorPr1';
  Map<String, Object?> interaction(
          {Object? a, String s = '3', String p = prior, String i = aid}) =>
      {
        't': 'ixn',
        'd': '',
        'i': i,
        's': s,
        'p': p,
        'a': a ??
            [
              {'i': 'Ex', 's': '0', 'd': 'Ex'}
            ]
      };
  final expectedIxn =
      ExpectedEvent.interaction(aid: aid, sn: 3, prior: prior, anchors: [
    {'i': 'Ex', 's': '0', 'd': 'Ex'}
  ]);

  test(
      'the interaction this device expects is signed, and one differing at all is not',
      () async {
    await expectedIxn.requireIn(km, saidified(interaction()));
    for (final wrong in [
      interaction(s: '4'),
      interaction(p: 'EOtherPriorOtherPriorOtherPriorOtherPrior12'),
      interaction(i: 'EOtherAidOtherAidOtherAidOtherAidOtherAid12'),
      interaction(a: [
        {'i': 'Ey', 's': '0', 'd': 'Ey'}
      ]),
    ]) {
      await expectLater(expectedIxn.requireIn(km, saidified(wrong)),
          throwsA(isA<NotTheEventExpected>()));
    }
  });

  test(
      'a rotation is checked against its own place, prior, keys and commitments',
      () async {
    final expected = ExpectedEvent.rotation(
        aid: aid, sn: 2, prior: prior, keys: [key], next: next);
    Map<String, Object?> rot({List<String>? n, String p = prior}) => {
          't': 'rot',
          'd': '',
          'i': aid,
          's': '2',
          'p': p,
          'kt': '1',
          'k': [key],
          'nt': '1',
          'n': n ?? next,
          'bt': '0',
          'br': [],
          'ba': [],
          'a': [],
        };
    await expected.requireIn(km, saidified(rot()));
    await expectLater(expected.requireIn(km, saidified(rot(n: [next[0]]))),
        throwsA(isA<NotTheEventExpected>()));
    // A recovery rotation follows a kept interaction rather than the tip: it
    // is the prior this device chose that counts.
    await expectLater(
        expected.requireIn(km,
            saidified(rot(p: 'EOtherPriorOtherPriorOtherPriorOtherPrior12'))),
        throwsA(isA<NotTheEventExpected>()));
  });
}
