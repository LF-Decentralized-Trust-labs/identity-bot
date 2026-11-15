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

  Future<Map<String, Object?>> owner(String who, String name,
          {bool signed = false}) async =>
      {
        'name': name,
        'aid': id(who),
        'key': keyOf('${who}0'),
        'next': [await km.nextKeyDigest(keyOf('${who}1'))],
        'next_key': keyOf('${who}1'),
        'after': [await km.nextKeyDigest(keyOf('${who}2'))],
        'signed': signed,
      };

  /// The terms and the rotation the org's agent would offer at a stage.
  Future<(Map<String, Object?>, List<int>)> offer(String stage,
      {String second = 'bob'}) async {
    final first = stage == 'rot1';
    final o = [await owner('alice', 'Alice'), await owner(second, 'Bob')];
    final groups = [for (final x in o) (first ? x['next'] : x['after']) as List];
    final raw = saidified({
      't': 'rot',
      'd': '',
      'i': aid,
      's': first ? '1' : '2',
      'p': prior,
      'kt': first ? '3' : '2',
      'k': first
          ? [keyOf('box1'), for (final x in o) x['key']]
          : [for (final x in o) x['next_key']],
      'nt': ceremonyNextThreshold(2, [for (final g in groups) g.cast<String>()]),
      'n': [for (final g in groups) ...g],
      'bt': '0',
      'br': [],
      'ba': [],
      'a': [],
    });
    final said = (jsonDecode(utf8.decode(raw)) as Map)['d'];
    return ({
      'status': 'signing', 'stage': stage, 'hand_over': true, 'threshold': 2, 'aid': aid,
      'sn': first ? '1' : '2', 'prior': prior, 'd': said,
      'own_key': keyOf('box1'), 'own_next_digest': '', 'toad': '0',
      'cuts': [], 'adds': [], 'anchors': [], 'owners': o,
    }, raw);
  }

  /// An organisation's agent that serves [terms] and the event, and records
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
    for (final stage in ['rot1', 'rot2']) {
      final (t, raw) = await offer(stage);
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
    final (t2, raw2) = await offer('rot2', second: 'mallory');
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
}
