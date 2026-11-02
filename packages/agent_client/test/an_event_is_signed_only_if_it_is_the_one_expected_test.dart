import 'dart:convert';

import 'dart:typed_data';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/the_key_events_this_device_makes.dart';
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
    'a field nobody asked for': founding(add: {'x': 'unasked'}),
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

  test('no event revealing a post-quantum key is signed before CESR has codes',
      () {
    expect(PostQuantumCodes.assigned, isFalse);
    expect(
        () => ExpectedEvent.postQuantumReserveReveal(
            aid: aid, sn: 2, prior: prior, postQuantumKey: 'Xpq', next: next),
        throwsA(isA<PostQuantumNotYet>()));
    for (final witnessed in [false, true]) {
      expect(
          () => ExpectedEvent.stageTwoRotation(
              aid: aid,
              sn: 2,
              prior: prior,
              classicalKey: key,
              postQuantumKey: 'Xpq',
              next: next,
              reCommitWitnessed: witnessed),
          throwsA(isA<PostQuantumNotYet>()));
    }
  });

  group('moving to a new phrase', () {
    final oldSeed = Bip39.mnemonicToSeed(
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
            .split(' '));
    final newSeed = Bip39.mnemonicToSeed(
        'legal winner thank year wave sausage worth useful legal winner thank yellow'
            .split(' '));
    String keyOf(Uint8List seed, int g) =>
        KeyManager.keyAt(seed, g).publicKeyEncoded;
    Future<List<String>> commitments(Uint8List seed, int c, int pq) async => [
          await km.nextKeyDigest(keyOf(seed, c)),
          (await km.postQuantumNext(
                  KeyManager.slip10Ed25519(seed, KeyPaths.postQuantum(pq))))
              .digest
        ];
    Map<String, Object?> rot(String k, List<String> n) => {
          't': 'rot',
          'd': '',
          'i': aid,
          's': '2',
          'p': prior,
          'kt': '1',
          'k': [k],
          'nt': '1',
          'n': n,
          'bt': '0',
          'br': [],
          'ba': [],
          'a': [],
        };

    test(
        'step 1 reveals the old phrase\'s key and commits to the new phrase only',
        () async {
      final toNew = await commitments(newSeed, 1, 0);
      final step1 = ExpectedEvent.rotation(
          aid: aid,
          sn: 2,
          prior: prior,
          keys: [keyOf(oldSeed, 2)],
          next: toNew);
      await step1.requireIn(km, saidified(rot(keyOf(oldSeed, 2), toNew)));
      // The new phrase's key was never committed to, so it cannot be in k.
      await expectLater(
          step1.requireIn(km, saidified(rot(keyOf(newSeed, 1), toNew))),
          throwsA(isA<NotTheEventExpected>()));
      // Still committing to the old phrase leaves its holder able to rotate.
      await expectLater(
          step1.requireIn(
              km,
              saidified(
                  rot(keyOf(oldSeed, 2), await commitments(oldSeed, 3, 2)))),
          throwsA(isA<NotTheEventExpected>()));
    });

    test('step 2 reveals the new phrase\'s key 1 and commits to its key 2',
        () async {
      final n = await commitments(newSeed, 2, 1);
      final step2 = ExpectedEvent.rotation(
          aid: aid, sn: 2, prior: prior, keys: [keyOf(newSeed, 1)], next: n);
      await step2.requireIn(km, saidified(rot(keyOf(newSeed, 1), n)));
      await expectLater(
          step2.requireIn(km, saidified(rot(keyOf(oldSeed, 3), n))),
          throwsA(isA<NotTheEventExpected>()));
    });
  });

  group('an event with several owners', () {
    // Sorted as ASCII: EAlice before EBob, so Bob is owner 1 (k[1], n[2..3]).
    const alice = 'EAliceAliceAliceAliceAliceAliceAliceAliceAl1';
    const bob = 'EBobBobBobBobBobBobBobBobBobBobBobBobBobBob12';
    const aliceKey = 'DAliceKeyAliceKeyAliceKeyAliceKeyAliceKey123';
    const bobKey = 'DBobKeyBobKeyBobKeyBobKeyBobKeyBobKeyBobKey1';
    const aliceN = [
      'EAliceNextAliceNextAliceNextAliceNextAlice12',
      'EAlicePqAlicePqAlicePqAlicePqAlicePqAlicePq1'
    ];
    const bobN = [
      'EBobNextBobNextBobNextBobNextBobNextBobNext1',
      'EBobPqBobPqBobPqBobPqBobPqBobPqBobPqBobPqBo1'
    ];
    const kt = '2';
    const nt = [
      ['1', '1'],
      ['1', '1']
    ];
    Map<String, Object?> groupFounding(
            {List<String>? k, List<String>? n, Object nt = nt}) =>
        {
          't': 'icp',
          'd': '',
          'i': '',
          's': '0',
          'kt': kt,
          'k': k ?? [aliceKey, bobKey],
          'nt': nt,
          'n': n ?? [...aliceN, ...bobN],
          'bt': '0',
          'b': [],
          'c': [],
          'a': [],
        };
    final layout = OwnerLayout([bob, alice], bob);
    final asBob = ExpectedEvent.asOneOfSeveralOwners(
        t: 'icp',
        layout: layout,
        myKey: bobKey,
        myNextClassical: bobN[0],
        myNextPostQuantum: bobN[1],
        kt: kt,
        nt: nt);

    test('each owner\'s place comes from the sorted owner list', () {
      expect(layout.owners, [alice, bob]);
      expect(layout.keyIndex, 1);
      expect(layout.nextClassicalIndex, 2);
      expect(layout.nextPostQuantumIndex, 3);
      expect(() => OwnerLayout([alice], bob), throwsArgumentError);
      expect(() => OwnerLayout([alice, alice, bob], bob), throwsArgumentError);
    });

    test('an owner signs the founding that holds its own keys where agreed',
        () async {
      await asBob.requireIn(km, saidified(groupFounding()));
    });

    final refused = <String, Map<String, Object?>>{
      'another owner\'s key at this owner\'s index':
          groupFounding(k: [bobKey, aliceKey]),
      'another key at this owner\'s index': groupFounding(
          k: [aliceKey, 'DAnotherKeyAnotherKeyAnotherKeyAnotherKey12']),
      'this owner\'s digests swapped':
          groupFounding(n: [...aliceN, bobN[1], bobN[0]]),
      'a third owner\'s key added': groupFounding(
          k: [aliceKey, bobKey, 'DThirdThirdThirdThirdThirdThirdThirdThird1']),
      'a threshold the ceremony did not agree': groupFounding(nt: '1'),
      'this owner\'s key at another owner\'s place too':
          groupFounding(k: [bobKey, bobKey]),
      'this owner\'s digest at another owner\'s place too':
          groupFounding(n: [bobN[0], aliceN[1], ...bobN]),
    };
    refused.forEach((why, fields) {
      test('a founding with $why is not signed', () async {
        await expectLater(asBob.requireIn(km, saidified(fields)),
            throwsA(isA<NotTheEventExpected>()));
      });
    });
  });
}
