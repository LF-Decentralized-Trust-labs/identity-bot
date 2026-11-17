import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/signing_a_ceremony_rotation.dart';
import 'package:agent_client/services/the_ceremony_this_device_agreed_to.dart';
import 'package:agent_client/services/the_event_this_device_expects.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

import 'support/a_witness.dart' show qb64;
import 'support/kel_events.dart';
import 'support/signing_with_seed.dart';
import 'support/the_core.dart';

// An invited owner's device reads what the ceremony is about, signs the first
// rotation only for the owners it names, and signs the second only if it is
// made of the same owners: a core that swaps one between the two gets no
// signature.
void main() {
  late KeyMath km;
  setUpAll(() async {
    km = await keyMathOf(await buildTheCore('ceremony-device-core'));
  });

  String id(String w) => 'E${w.padRight(43, w[0])}';
  Uint8List seedOf(String w) => Uint8List.fromList(
      utf8.encode(w).followedBy(List.filled(32, 0)).take(32).toList());
  String keyOf(String w) =>
      qb64('D', Uint8List.fromList(ed.public(ed.newKeyFromSeed(seedOf(w))).bytes));

  const aid = 'EBoxIdentity000000000000000000000000000000';
  const prior = 'EPrior00000000000000000000000000000000000';
  final alice = id('alice'), bob = id('bob');

  // The core's derivation runs as a process, so each one is made once.
  final pqDigests = <String, String>{};
  Future<String> pqDigest(String w) async => pqDigests[w] ??=
      (await km.postQuantumNext(seedOf(w))).digest;

  Future<Map<String, Object?>> owner(String who, String name,
          {bool signed = false}) async =>
      {
        'name': name,
        'aid': id(who),
        'key': keyOf('${who}0'),
        // As a phone commits: the classical digest, then its post-quantum
        // partner, which the core's own code derives from a seed.
        'next': [
          await km.nextKeyDigest(keyOf('${who}1')),
          await pqDigest('${who}P1')
        ],
        'next_key': keyOf('${who}1'),
        'after': [
          await km.nextKeyDigest(keyOf('${who}2')),
          await pqDigest('${who}P2')
        ],
        'signed': signed,
      };

  /// The terms and the rotation the organisation's Identity Agent would offer at a stage.
  Future<(Map<String, Object?>, List<int>)> offer(String stage,
      {String second = 'bob',
      String? priorOf,
      List<Object?>? anchors,
      List<String> cuts = const []}) async {
    final first = stage == 'rot1';
    final o = [await owner('alice', 'Alice'), await owner(second, 'Bob')];
    final groups = [for (final x in o) (first ? x['next'] : x['after']) as List];
    final seals = anchors ??
        (first
            ? [for (final x in o) {'i': x['aid'], 's': '0', 'd': x['aid']}]
            : <Object?>[]);
    final raw = saidified({
      't': 'rot',
      'd': '',
      'i': aid,
      's': first ? '1' : '2',
      'p': priorOf ?? prior,
      'kt': first ? '3' : '2',
      'k': first
          ? [keyOf('box1'), for (final x in o) x['key']]
          : [for (final x in o) x['next_key']],
      'nt': ceremonyNextThreshold(2, [for (final g in groups) g.cast<String>()]),
      'n': [for (final g in groups) ...g],
      'bt': '0',
      'br': cuts,
      'ba': [],
      'a': seals,
    });
    final said = (jsonDecode(utf8.decode(raw)) as Map)['d'];
    return ({
      'status': 'signing', 'stage': stage, 'hand_over': true, 'threshold': 2, 'aid': aid,
      'sn': first ? '1' : '2', 'prior': priorOf ?? prior, 'd': said,
      'own_key': keyOf('box1'), 'own_next_digests': <String>[], 'toad': '0',
      'cuts': cuts, 'adds': [], 'anchors': seals, 'owners': o,
    }, raw);
  }

  /// An organisation's Identity Agent that serves [terms] and the event, and records
  /// what it is sent.
  (MockClient, List<http.Request>) org(Map<String, Object?> terms, List<int> raw) {
    final seen = <http.Request>[];
    return (
      MockClient((r) async {
        seen.add(r);
        if (r.url.path.endsWith('ceremony-terms')) {
          return http.Response(jsonEncode(terms), 200);
        }
        if (r.url.path.endsWith('ceremony-event')) {
          return http.Response(
              jsonEncode({'stage': terms['stage'], 'raw_b64': base64Encode(raw), 'd': terms['d']}),
              200);
        }
        return http.Response(jsonEncode({'status': 'waiting_for_signatures'}), 202);
      }),
      seen
    );
  }

  CeremonyDevice deviceOver(MockClient client, CeremonyAgreements agreements,
      {List<int>? signed}) =>
      CeremonyDevice(
        client: client,
        km: km,
        agreements: agreements,
        signWithDeviceKey: (token, {required generation, required raw}) async {
          signed?.addAll([generation]);
          return signingWithSeed(seedOf(generation == 0 ? 'alice0' : 'alice1'))(
              Uint8List.fromList(raw));
        },
      );

  test('what the ceremony says is read, and its being over is not an error', () async {
    final (t, raw) = await offer('rot1');
    final (client, _) = org(t, raw);
    final reading = await deviceOver(client, InMemoryCeremonyAgreements())
        .read('http://org', 'tok');
    expect(reading!.status, 'signing');
    final terms = reading.terms!;
    expect(terms.owners.map((o) => o.name), ['Alice', 'Bob']);
    expect(terms.handOver, isTrue);
    expect(terms.signedCount, 0);
    final none = MockClient((_) async => http.Response('', 404));
    expect(await deviceOver(none, InMemoryCeremonyAgreements()).read('http://org', 'tok'),
        isNull);
    final over = MockClient((_) async => http.Response('{"status":"applied"}', 200));
    final done = await deviceOver(over, InMemoryCeremonyAgreements()).read('http://org', 'tok');
    expect(done!.status, 'applied');
    expect(done.terms, isNull);
  });

  test('signs both rotations of the same owners, with the key of each generation', () async {
    final agreements = InMemoryCeremonyAgreements();
    final generations = <int>[];
    String? firstDigest;
    for (final stage in ['rot1', 'rot2']) {
      // The second rotation follows the first: its prior is the first's digest.
      final (t, raw) = await offer(stage, priorOf: firstDigest);
      firstDigest ??= '${t['d']}';
      final (client, seen) = org(t, raw);
      final device = deviceOver(client, agreements, signed: generations);
      final out = await device.sign(
          'http://org', 'tok', CeremonyTerms.fromJson(t), me: alice);
      expect(out.status, 'waiting_for_signatures');
      expect(seen.where((r) => r.method == 'POST'), hasLength(1));
    }
    expect(generations, [0, 1]);
  });

  test('refuses the second rotation when an owner was swapped after the first', () async {
    final agreements = InMemoryCeremonyAgreements();
    final (t1, raw1) = await offer('rot1');
    await deviceOver(org(t1, raw1).$1, agreements)
        .sign('http://org', 'tok', CeremonyTerms.fromJson(t1), me: alice);
    final (t2, raw2) = await offer('rot2', second: 'mallory', priorOf: '${t1['d']}');
    final (client, seen) = org(t2, raw2);
    final signed = <int>[];
    await expectLater(
        deviceOver(client, agreements, signed: signed)
            .sign('http://org', 'tok', CeremonyTerms.fromJson(t2), me: alice),
        throwsA(isA<CeremonyNotSigned>()));
    expect(signed, isEmpty);
    expect(seen.where((r) => r.method == 'POST'), isEmpty);
  });

  test('will not sign a second rotation it was never shown the first of', () async {
    final (t2, raw2) = await offer('rot2');
    final (client, seen) = org(t2, raw2);
    await expectLater(
        deviceOver(client, InMemoryCeremonyAgreements())
            .sign('http://org', 'tok', CeremonyTerms.fromJson(t2), me: alice),
        throwsA(isA<CeremonyNotSigned>()));
    expect(seen.where((r) => r.method == 'POST'), isEmpty);
  });

  test('will not sign as a device the terms do not name', () async {
    final (t, raw) = await offer('rot1');
    final (client, _) = org(t, raw);
    await expectLater(
        deviceOver(client, InMemoryCeremonyAgreements())
            .sign('http://org', 'tok', CeremonyTerms.fromJson(t), me: id('carol')),
        throwsA(isA<CeremonyNotSigned>()));
  });

  test('a rotation that is not the one the terms describe is not signed', () async {
    final (t, _) = await offer('rot1');
    final (_, other) = await offer('rot1', second: 'mallory');
    final (client, seen) = org(t, other);
    await expectLater(
        deviceOver(client, InMemoryCeremonyAgreements())
            .sign('http://org', 'tok', CeremonyTerms.fromJson(t), me: alice),
        throwsA(isA<CeremonyEventRefused>()));
    expect(seen.where((r) => r.method == 'POST'), isEmpty);
    expect(bob, isNotEmpty);
  });

  /// A first rotation signed, then [second] offered: whether it is signed.
  Future<(bool, List<http.Request>)> secondIsSigned(
      Future<(Map<String, Object?>, List<int>)> Function(String firstDigest) second,
      {Map<String, Object?>? firstTerms}) async {
    final agreements = InMemoryCeremonyAgreements();
    final (t1, raw1) = await offer('rot1');
    await deviceOver(org(t1, raw1).$1, agreements)
        .sign('http://org', 'tok', CeremonyTerms.fromJson(t1), me: alice);
    final (t2, raw2) = await second('${t1['d']}');
    final (client, seen) = org(t2, raw2);
    try {
      await deviceOver(client, agreements)
          .sign('http://org', 'tok', CeremonyTerms.fromJson(t2), me: alice);
      return (true, seen);
    } on CeremonyNotSigned {
      return (false, seen);
    }
  }

  test('the second rotation must follow the first, and nothing else about it may differ',
      () async {
    final ok = await secondIsSigned((d) => offer('rot2', priorOf: d));
    expect(ok.$1, isTrue);
    final unrelated = await secondIsSigned((d) => offer('rot2', priorOf: 'EElsewhere0000000000000000000000000000000000'));
    expect(unrelated.$1, isFalse);
    expect(unrelated.$2.where((r) => r.method == 'POST'), isEmpty);
    final anchoring = await secondIsSigned((d) => offer('rot2', priorOf: d, anchors: [{'i': alice, 's': '0', 'd': alice}]));
    expect(anchoring.$1, isFalse);
    final cutting = await secondIsSigned((d) => offer('rot2', priorOf: d, cuts: [id('witness')]));
    expect(cutting.$1, isFalse);
  });

  test('a first rotation is refused if it anchors something that is not an owner, leaves an owner out, or cuts a witness', () async {
    for (final (name, anchors, cuts) in [
      ('a stray seal', <Object?>[{'i': id('alice'), 's': '0', 'd': id('alice')}, {'i': id('bob'), 's': '0', 'd': id('bob')}, {'x': 1}], <String>[]),
      ('a missing owner', <Object?>[{'i': id('alice'), 's': '0', 'd': id('alice')}], <String>[]),
      ('a cut witness', null, [id('witness')]),
    ]) {
      final (t, raw) = await offer('rot1', anchors: anchors, cuts: cuts);
      final (client, seen) = org(t, raw);
      await expectLater(
          deviceOver(client, InMemoryCeremonyAgreements())
              .sign('http://org', 'tok', CeremonyTerms.fromJson(t), me: alice),
          throwsA(isA<CeremonyNotSigned>()),
          reason: name);
      expect(seen.where((r) => r.method == 'POST'), isEmpty, reason: name);
    }
  });

  test('a first rotation offered again with other owners is not signed', () async {
    final agreements = InMemoryCeremonyAgreements();
    final (t1, raw1) = await offer('rot1');
    await deviceOver(org(t1, raw1).$1, agreements)
        .sign('http://org', 'tok', CeremonyTerms.fromJson(t1), me: alice);
    final (t1b, raw1b) = await offer('rot1', second: 'mallory');
    final (client, seen) = org(t1b, raw1b);
    await expectLater(
        deviceOver(client, agreements)
            .sign('http://org', 'tok', CeremonyTerms.fromJson(t1b), me: alice),
        throwsA(isA<CeremonyNotSigned>()));
    expect(seen.where((r) => r.method == 'POST'), isEmpty);
  });

  test('a first rotation offered again at another place is not signed', () async {
    final agreements = InMemoryCeremonyAgreements();
    final (t1, raw1) = await offer('rot1');
    await deviceOver(org(t1, raw1).$1, agreements)
        .sign('http://org', 'tok', CeremonyTerms.fromJson(t1), me: alice);
    // The same owners and keys, after another event: a second history.
    final (t1b, raw1b) = await offer('rot1', priorOf: 'E${'B' * 43}');
    final (client, seen) = org(t1b, raw1b);
    await expectLater(
        deviceOver(client, agreements)
            .sign('http://org', 'tok', CeremonyTerms.fromJson(t1b), me: alice),
        throwsA(isA<CeremonyNotSigned>()));
    expect(seen.where((r) => r.method == 'POST'), isEmpty);
  });

  test('a change that leaves out this phone\'s post-quantum commitment is not signed', () async {
    for (final stage in ['rot1', 'rot2']) {
      for (final field in ['next', 'after']) {
        // Only the digest that matters at the stage is checked against the
        // event, but the person agreed to both: a change that drops either is
        // not the change a phone asked for.
        final (t, raw) = await offer(stage);
        final owners = (t['owners'] as List).cast<Map<String, Object?>>();
        owners.first[field] = [(owners.first[field] as List).first];
        final (client, _) = org(t, raw);
        final signed = <int>[];
        final device = deviceOver(client, InMemoryCeremonyAgreements(), signed: signed);
        final reading = await device.read('http://org', 'tok');
        await expectLater(
            device.sign('http://org', 'tok', reading!.terms!, me: alice),
            throwsA(isA<CeremonyNotSigned>().having(
                (e) => e.reason, 'reason', contains('quantum'))),
            reason: '$stage with $field dropped');
        expect(signed, isEmpty, reason: 'the key was asked to sign');
      }
    }
  });

  test('another owner leaving out its commitment is not this phone\'s to refuse', () async {
    // What this phone commits to is its own; a co-owner whose device made no
    // post-quantum commitment is held to its classical key (ADR-061 section 6).
    final (t, raw) = await offer('rot1');
    final owners = (t['owners'] as List).cast<Map<String, Object?>>();
    owners.last['next'] = [(owners.last['next'] as List).first];
    final (client, _) = org(t, raw);
    final signed = <int>[];
    final device = deviceOver(client, InMemoryCeremonyAgreements(), signed: signed);
    final terms = (await device.read('http://org', 'tok'))!.terms!;
    expect(terms.leavesOutThePostQuantumCommitmentOf(alice), isNull);
    expect(terms.leavesOutThePostQuantumCommitmentOf(bob), isNotNull);
  });
}
