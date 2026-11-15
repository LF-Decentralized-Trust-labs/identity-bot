import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/signing_a_ceremony_rotation.dart';
import 'package:agent_client/services/the_event_this_device_expects.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

import 'support/a_witness.dart' show qb64;
import 'support/kel_events.dart';
import 'support/the_core.dart';

// An invited owner's device signs the rotation an ownership ceremony prepared
// only if it is exactly the one the device recorded the ceremony as, in either
// stage, and returns its signature at the place the event gives it.
void main() {
  late KeyMath km;
  setUpAll(() async {
    km = await keyMathOf(await buildTheCore('ceremony-core'));
  });

  String id(String w) => 'E${w.padRight(43, w[0])}';
  Uint8List seedOf(String w) => Uint8List.fromList(
      utf8.encode(w).followedBy(List.filled(32, 0)).take(32).toList());
  String keyOf(String w) => qb64('D', Uint8List.fromList(ed.public(ed.newKeyFromSeed(seedOf(w))).bytes));

  const aid = 'EBoxIdentity000000000000000000000000000000';
  const prior = 'EPrior00000000000000000000000000000000000';
  final alice = id('alice'), bob = id('bob');

  Future<Map<String, CeremonyOwner>> owners({bool pq = false}) async => {
        alice: CeremonyOwner(keyOf('alice0'), [
          await km.nextKeyDigest(keyOf('alice1')),
          if (pq) id('alicepq')
        ],
            nextKey: keyOf('alice1'),
            after: [await km.nextKeyDigest(keyOf('alice2'))]),
        bob: CeremonyOwner(keyOf('bob0'), [
          await km.nextKeyDigest(keyOf('bob1')),
          if (pq) id('bobpq')
        ],
            nextKey: keyOf('bob1'),
            after: [await km.nextKeyDigest(keyOf('bob2'))]),
      };

  Future<ExpectedEvent> expectedAs(String me, CeremonyStage stage,
      {bool pq = false}) async =>
      ExpectedEvent.asAnOwnerInACeremony(
          stage: stage,
          handOver: true,
          aid: aid,
          sn: stage == CeremonyStage.first ? 1 : 2,
          prior: prior,
          ownKey: keyOf('box1'),
          owners: await owners(pq: pq),
          me: me,
          threshold: 2);

  // The rotation the core prepares, built the way its code builds it.
  Future<Map<String, Object?>> rotation(CeremonyStage stage,
      {bool pq = false, List<String>? k}) async {
    final o = await owners(pq: pq);
    final first = stage == CeremonyStage.first;
    final groups = first
        ? [o[alice]!.next, o[bob]!.next]
        : [o[alice]!.after, o[bob]!.after];
    return {
      't': 'rot',
      'd': '',
      'i': aid,
      's': first ? '1' : '2',
      'p': prior,
      'kt': first ? '3' : '2',
      'k': k ??
          (first
              ? [keyOf('box1'), o[alice]!.key, o[bob]!.key]
              : [o[alice]!.nextKey, o[bob]!.nextKey]),
      'nt': ceremonyNextThreshold(2, groups),
      'n': [for (final g in groups) ...g],
      'bt': '0',
      'br': [],
      'ba': [],
      'a': [],
    };
  }

  test('the first rotation, with and without post-quantum digests, is the one expected', () async {
    for (final pq in [false, true]) {
      await (await expectedAs(alice, CeremonyStage.first, pq: pq))
          .requireIn(km, saidified(await rotation(CeremonyStage.first, pq: pq)));
    }
  });

  test('a threshold that counts owners when each commits once and shares when it commits twice', () {
    expect(ceremonyNextThreshold(2, [['a'], ['b']]), '2');
    expect(ceremonyNextThreshold(2, [['a', 'p'], ['b', 'q']]), [
      {'1/2': ['1', '1']},
      {'1/2': ['1', '1']}
    ]);
  });

  test('each owner signs at the place the event gives it', () async {
    final a1 = await expectedAs(alice, CeremonyStage.first);
    final b1 = await expectedAs(bob, CeremonyStage.first);
    expect([a1.place!.index, a1.place!.currentOnly], [1, true]);
    expect([b1.place!.index, b1.place!.currentOnly], [2, true]);
    // In the second rotation an owner opens its own digest of the first.
    final a2 = await expectedAs(alice, CeremonyStage.second);
    final b2 = await expectedAs(bob, CeremonyStage.second);
    expect([a2.place!.index, a2.place!.ondex, a2.place!.currentOnly], [0, 0, false]);
    expect([b2.place!.index, b2.place!.ondex, b2.place!.currentOnly], [1, 1, false]);
    final pa = await expectedAs(alice, CeremonyStage.second, pq: true);
    final pb = await expectedAs(bob, CeremonyStage.second, pq: true);
    expect([pa.place!.ondex, pb.place!.ondex], [0, 2]);
  });

  final refused = <String, Future<Map<String, Object?>> Function()>{
    'a key of the core\'s own in place of an owner\'s': () async =>
        rotation(CeremonyStage.first, k: [keyOf('box1'), keyOf('mallory'), keyOf('bob0')]),
    'the owners\' keys the wrong way round': () async =>
        rotation(CeremonyStage.first, k: [keyOf('box1'), keyOf('bob0'), keyOf('alice0')]),
    'the box key left in the next keys': () async => {
          ...await rotation(CeremonyStage.first),
          'n': [id('boxnext'), ...(await rotation(CeremonyStage.first))['n'] as List],
        },
    'a threshold nobody agreed': () async =>
        {...await rotation(CeremonyStage.first), 'nt': '1'},
    'a seal nobody agreed': () async => {
          ...await rotation(CeremonyStage.first),
          'a': [{'i': id('mallory'), 's': '0', 'd': id('mallory')}]
        },
  };
  refused.forEach((why, build) {
    test('a first rotation with $why is not signed', () async {
      await expectLater(
          (await expectedAs(alice, CeremonyStage.first)).requireIn(km, saidified(await build())),
          throwsA(isA<NotTheEventExpected>()));
    });
  });

  test('the second rotation is signed alone by the owners, and a core that keeps its key in it is refused', () async {
    final e = await expectedAs(bob, CeremonyStage.second);
    await e.requireIn(km, saidified(await rotation(CeremonyStage.second)));
    await expectLater(
        e.requireIn(km, saidified(await rotation(CeremonyStage.second, k: [keyOf('box2'), keyOf('alice1'), keyOf('bob1')]))),
        throwsA(isA<NotTheEventExpected>()));
  });

  group('the step a device takes', () {
    Future<(MockClient, List<http.Request>)> core(Map<String, Object?> fields,
        {String stage = 'rot1'}) async {
      final raw = saidified(fields);
      final said = (jsonDecode(utf8.decode(raw)) as Map)['d'];
      final seen = <http.Request>[];
      return (
        MockClient((r) async {
          seen.add(r);
          if (r.method == 'GET') {
            return http.Response(
                jsonEncode({'stage': stage, 'raw_b64': base64Encode(raw), 'd': said}), 200);
          }
          return http.Response(jsonEncode({'status': 'recorded', 'next_stage': 'rot2'}), 201);
        }),
        seen
      );
    }

    test('signs what it agreed to and sends its signature with the event\'s digest', () async {
      final (client, seen) = await core(await rotation(CeremonyStage.first));
      final out = await signTheCeremonyRotation(client, 'http://core', token: 'tok',
          stage: CeremonyStage.first,
          sign: signingWithSeed(seedOf('alice0')),
          km: km,
          expected: await expectedAs(alice, CeremonyStage.first));
      expect(out.nextStage, 'rot2');
      final sent = jsonDecode(seen.last.body) as Map;
      expect((sent['sigs'] as List).length, 1);
      expect(sent['d'], isNotEmpty);
    });

    test('signs nothing, and sends nothing, for a rotation it did not agree to', () async {
      final (client, seen) = await core(
          await rotation(CeremonyStage.first, k: [keyOf('box1'), keyOf('mallory'), keyOf('bob0')]));
      await expectLater(
          signTheCeremonyRotation(client, 'http://core', token: 'tok',
              stage: CeremonyStage.first,
              sign: signingWithSeed(seedOf('alice0')),
              km: km,
              expected: await expectedAs(alice, CeremonyStage.first)),
          throwsA(isA<CeremonyEventRefused>()));
      expect(seen.where((r) => r.method == 'POST'), isEmpty);
    });

    test('does not sign the second rotation when the core offers the first', () async {
      final (client, seen) = await core(await rotation(CeremonyStage.first));
      await expectLater(
          signTheCeremonyRotation(client, 'http://core', token: 'tok',
              stage: CeremonyStage.second,
              sign: signingWithSeed(seedOf('alice1')),
              km: km,
              expected: await expectedAs(alice, CeremonyStage.second)),
          throwsA(isA<CeremonyEventRefused>()));
      expect(seen.where((r) => r.method == 'POST'), isEmpty);
    });
  });
}
