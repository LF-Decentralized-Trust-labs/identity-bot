import 'dart:convert';

import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/the_event_this_device_expects.dart';
import 'package:test/test.dart';

import 'support/kel_events.dart';
import 'support/the_core.dart';

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
    km = await keyMathOf(await buildTheCore('expects-core'));
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
