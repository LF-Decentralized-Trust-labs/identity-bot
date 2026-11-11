import 'dart:convert';

import 'dart:typed_data';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/the_key_events_this_device_makes.dart';
import 'package:agent_client/services/the_event_this_device_expects.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:test/test.dart';

import 'support/a_witness.dart';
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
    // Sorted as ASCII: alice, bob, carol, so bob is owner 1 (k[1], n[2..3]).
    String id(String w) => 'E${w.padRight(43, w[0])}';
    // A real key for each name: a made-up one is not on the curve or of small
    // order, which keri-go does not read as a key.
    String keyOf(String w) => qb64(
        'D',
        Uint8List.fromList(ed
            .public(ed.newKeyFromSeed(Uint8List.fromList(utf8
                .encode(w)
                .followedBy(List.filled(32, 0))
                .take(32)
                .toList())))
            .bytes));
    final alice = id('alice'), bob = id('bob'), carol = id('carol');
    OwnerKeys keysOf(String w) =>
        OwnerKeys(keyOf(w), id('${w}next'), id('${w}pq'));
    final agreed = {
      carol: keysOf('carol'),
      bob: keysOf('bob'),
      alice: keysOf('alice'),
    };
    // Any two of three, stage one (ADR-061 section 6).
    const kt = '2';
    const nt = [
      {
        '1/2': ['1', '1']
      },
      {
        '1/2': ['1', '1']
      },
      {
        '1/2': ['1', '1']
      }
    ];
    final ks = [keyOf('alice'), keyOf('bob'), keyOf('carol')];
    final ns = [
      for (final w in ['alice', 'bob', 'carol']) ...[
        id('${w}next'),
        id('${w}pq')
      ]
    ];
    Map<String, Object?> groupFounding(
            {List<String>? k, List<String>? n, Object nt = nt}) =>
        {
          't': 'icp',
          'd': '',
          'i': '',
          's': '0',
          'kt': kt,
          'k': k ?? ks,
          'nt': nt,
          'n': n ?? ns,
          'bt': '0',
          'b': [],
          'c': [],
          'a': [],
        };
    final asBob = ExpectedEvent.asOneOfSeveralOwners(
        t: 'icp', agreed: agreed, me: bob, mine: keysOf('bob'), kt: kt, nt: nt);

    test('each owner\'s place comes from the sorted owner list', () {
      final layout = asBob.layout!;
      expect(layout.owners, [alice, bob, carol]);
      expect(layout.keyIndex, 1);
      expect(layout.nextClassicalIndex, 2);
      expect(layout.nextPostQuantumIndex, 3);
      expect(() => OwnerLayout([alice], bob), throwsArgumentError);
      expect(() => OwnerLayout([alice, alice, bob], bob), throwsArgumentError);
    });

    test('an owner signs the founding that holds every agreed key in place',
        () async {
      await asBob.requireIn(km, saidified(groupFounding()));
    });

    test(
        'an owner whose record disagrees with its phrase, or names a key twice, prepares nothing',
        () {
      expect(
          () => ExpectedEvent.asOneOfSeveralOwners(
              t: 'icp',
              agreed: agreed,
              me: bob,
              mine: keysOf('bobby'),
              kt: kt,
              nt: nt),
          throwsArgumentError);
      expect(
          () => ExpectedEvent.asOneOfSeveralOwners(
              t: 'icp',
              agreed: {...agreed, carol: keysOf('bob')},
              me: bob,
              mine: keysOf('bob'),
              kt: kt,
              nt: nt),
          throwsArgumentError);
    });

    final refused = <String, Map<String, Object?>>{
      // Alice and Bob would meet "any two" without Carol.
      'an owner who is not signing replaced by another key':
          groupFounding(k: [ks[0], ks[1], keyOf('mallory')]),
      'an owner who is not signing given other next digests':
          groupFounding(n: [...ns.take(4), id('mallorynext'), id('mallorypq')]),
      'another owner\'s key at this owner\'s index':
          groupFounding(k: [ks[1], ks[0], ks[2]]),
      'this owner\'s digests swapped':
          groupFounding(n: [ns[0], ns[1], ns[3], ns[2], ns[4], ns[5]]),
      'a fourth owner\'s key added': groupFounding(k: [...ks, keyOf('dave')]),
      'a threshold the ceremony did not agree': groupFounding(nt: '1'),
    };
    refused.forEach((why, fields) {
      test('a founding with $why is not signed', () async {
        await expectLater(asBob.requireIn(km, saidified(fields)),
            throwsA(isA<NotTheEventExpected>()));
      });
    });
  });

  // What the parser already refuses, refused by this device's own check too,
  // so that neither depends on the other.
  group('the device\'s own check, on events the parser would refuse', () {
    ParsedEvent parsed(List<List<Object?>> fields, {String i = 'Ed'}) =>
        ParsedEvent.fromJson({
          't': 'icp',
          'd': 'Ed',
          'i': i,
          's': 0,
          'fields': [
            for (final f in fields) {'name': f[0], 'value': f[1]}
          ]
        });
    final good = [
      ['v', 'KERI10JSON000000_'],
      ['t', 'icp'],
      ['d', 'Ed'],
      ['i', 'Ed'],
      ['s', '0'],
      ['kt', '1'],
      [
        'k',
        [key]
      ],
      ['nt', '1'],
      ['n', next],
      ['bt', '0'],
      ['b', []],
      ['c', []],
      [
        'a',
        [anchor]
      ],
    ];

    test('the expected founding passes', () {
      expect(expectedFounding.differenceFrom(parsed(good)), isNull);
    });

    test('a field nobody asked for is refused', () {
      expect(
          expectedFounding.differenceFrom(parsed([
            ...good,
            ['x', 'unasked']
          ])),
          contains('not asked for'));
    });

    test('a field carried twice is refused', () {
      expect(
          expectedFounding.differenceFrom(parsed([
            ...good,
            ['bt', '0']
          ])),
          contains('twice'));
    });

    test('a field left out is refused', () {
      expect(
          expectedFounding.differenceFrom(parsed([
            for (final f in good)
              if (f[0] != 'c') f
          ])),
          contains('no "c"'));
    });

    test('a key that is not Ed25519 is refused while no other code exists', () {
      final pq = ExpectedEvent.founding(
          keys: ['1AAPpostquantumpostquantumpostquantumpostqua'],
          next: next,
          anchors: [anchor]);
      expect(
          pq.differenceFrom(parsed([
            for (final f in good)
              f[0] == 'k'
                  ? [
                      'k',
                      ['1AAPpostquantumpostquantumpostquantumpostqua']
                    ]
                  : f
          ])),
          contains('not Ed25519'));
    });
  });
}
