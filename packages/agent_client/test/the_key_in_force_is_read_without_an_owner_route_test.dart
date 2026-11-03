import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/signing_an_event.dart';
import 'package:agent_client/services/the_identity_this_device_holds.dart';
import 'package:agent_client/services/the_key_events_this_device_makes.dart';
import 'package:agent_client/services/the_key_state_this_device_reads.dart';
import 'package:agent_client/services/the_witnesses_of_this_devices_events.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

import 'support/a_core_that_misleads.dart';
import 'support/a_witness.dart';
import 'support/the_core.dart';

/// Every read an app makes of its core, so a test can say none was an owner
/// route.
class _RecordsWhatItReads extends http.BaseClient {
  _RecordsWhatItReads(this._inner);
  final http.Client _inner;
  final reads = <String>[];
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    if (request.method == 'GET') reads.add(request.url.path);
    return _inner.send(request);
  }
}

LoggedEvent _ev(int sn, String d, String ilk,
        {List<String> w = const [], int toad = 0}) =>
    LoggedEvent(sn, d, ilk, const ['Dkey'], const [], w, toad);

void main() {
  group('copies of a log are combined as ADR-061 section 9 says', () {
    const aid = 'EAid';
    final names = [for (var i = 1; i <= 3; i++) 'B${'$i' * 43}'];
    final icp = _ev(0, 'E0', 'icp', w: names, toad: 2);
    final ixn = _ev(1, 'E1', 'ixn', w: names, toad: 2);
    final rot = _ev(2, 'E2', 'rot', w: names, toad: 2);
    final rival = _ev(2, 'E2rival', 'rot', w: names, toad: 2);
    LogCopy at(String w, List<LoggedEvent> e) {
      final name = names[int.parse(w.substring(1)) - 1];
      return LogCopy('witness $name', e, witness: name);
    }

    test('a copy that stops early has not caught up, and is not a conflict',
        () {
      final c = TheKeyStateThisDeviceReads.combine(aid, [
        at('w1', [icp, ixn, rot]),
        at('w2', [icp, ixn, rot]),
        at('w3', [icp]),
      ]);
      expect((c.establishment.digest, c.tip.digest, c.corroborated),
          ('E2', 'E2', true));
    });

    test(
        'the newest establishment event too few witnesses hold is not in '
        'force, and where this device made it, nothing is signed', () {
      final copies = [
        at('w1', [icp, ixn, rot]),
        at('w2', [icp, ixn]),
        at('w3', [icp, ixn]),
      ];
      final c = TheKeyStateThisDeviceReads.combine(aid, copies);
      expect((c.establishment.digest, c.tip.digest), ('E0', 'E1'));
      expect(
          () => TheKeyStateThisDeviceReads.combine(aid, copies,
              made: [(sn: 2, digest: 'E2')]),
          throwsA(isA<TheCopiesAreBehindThisDevice>()));
    });

    test('two establishment events at one place stop signing', () {
      expect(
          () => TheKeyStateThisDeviceReads.combine(aid, [
                at('w1', [icp, ixn, rot]),
                at('w2', [icp, ixn, rival]),
                at('w3', [icp, ixn, rot]),
              ]),
          throwsA(
              isA<TheLogHasTwoHistories>().having((e) => e.sn, 'place', 2)));
      // This device's own record is one more source.
      expect(
          () => TheKeyStateThisDeviceReads.combine(aid, [
                at('w1', [icp, ixn, rot]),
                at('w2', [icp, ixn, rot]),
              ], made: [
                (sn: 2, digest: 'E2rival')
              ]),
          throwsA(isA<TheLogHasTwoHistories>()));
    });

    test(
        'interactions are taken as far as every copy reaching them agrees, '
        'and an establishment event this device made cannot be replaced', () {
      final a = _ev(3, 'E3a', 'ixn', w: names, toad: 2);
      final b = _ev(3, 'E3b', 'ixn', w: names, toad: 2);
      final c = TheKeyStateThisDeviceReads.combine(aid, [
        at('w1', [icp, ixn, rot, a]),
        at('w2', [icp, ixn, rot, b]),
      ]);
      expect(c.tip.digest, 'E2');
      final replaced = _ev(2, 'E2ixn', 'ixn', w: names, toad: 2);
      expect(
          () => TheKeyStateThisDeviceReads.combine(aid, [
                at('w1', [icp, ixn, replaced]),
                at('w2', [icp, ixn, replaced]),
              ], made: [
                (sn: 0, digest: 'E0'),
                (sn: 2, digest: 'E2')
              ]),
          throwsA(anyOf(isA<TheLogHasTwoHistories>(),
              isA<TheCopiesAreBehindThisDevice>())));
    });

    test('nothing read from the witnesses is no key state, unless asked', () {
      final core = LogCopy('the discovery record', [icp, ixn]);
      expect(() => TheKeyStateThisDeviceReads.combine(aid, [core]),
          throwsA(isA<TheWitnessesDoNotSay>()));
      final c = TheKeyStateThisDeviceReads.combine(aid, [core],
          acceptTheCoreAlone: true);
      expect((c.tip.digest, c.corroborated), ('E1', false));
    });
  });

  group('against a real core and witnesses', () {
    late String bin;
    late KeyMath km;
    late AWitness w1, w2, w3;
    late ACore core;
    late _RecordsWhatItReads reads;
    late TheWitnessesOfThisDevicesEvents witnesses;

    setUpAll(() async {
      bin = await buildTheCore('key-state-core', dev: true);
      km = await keyMathOf(bin);
      w1 = await AWitness.start(km);
      w2 = await AWitness.start(km);
      w3 = await AWitness.start(km);
      witnesses = TheWitnessesOfThisDevicesEvents(
          http.Client(),
          km,
          KnownWitnesses({
            for (final w in [w1, w2, w3]) w.aid: w.base
          }));
    });

    tearDownAll(() async {
      for (final w in [w1, w2, w3]) {
        await w.close();
      }
    });

    setUp(() async {
      FlutterSecureStorage.setMockInitialValues({});
      SharedPreferences.setMockInitialValues({});
      for (final w in [w1, w2, w3]) {
        w.offline = false;
        w.forgetAll();
      }
      core = await anotherCore(bin, km);
      reads = _RecordsWhatItReads(core.client);
    });

    tearDown(() => core.close());

    final seed = Bip39.mnemonicToSeed(
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
            .split(' '));
    const anchor = [
      {
        'i': 'EAnchoredAnchoredAnchoredAnchoredAnchored12',
        's': '0',
        'd': 'EAnchoredAnchoredAnchoredAnchoredAnchored12'
      }
    ];

    TheKeyEventsThisDeviceMakes makes() =>
        TheKeyEventsThisDeviceMakes(reads, core.base, km,
            witnesses: witnesses, held: TheIdentityThisDeviceHolds());
    TheKeyStateThisDeviceReads reader() =>
        TheKeyStateThisDeviceReads(reads, km, core.base);

    test(
        'the key in force is learned with no owner read: from this device\'s '
        'own record, and from the witnesses and the discovery record when the '
        'record cannot answer', () async {
      final m = makes();
      await m.found(seed, witnesses: [w1.aid, w2.aid, w3.aid], toad: 2);
      var state = await reader().read(seed);
      expect(state.fromItsOwnRecord, isTrue);
      final rot = await m.rotate(seed,
          aid: state.aid,
          generation: state.generation,
          afterSn: state.tip.sn,
          afterDigest: state.tip.digest,
          toad: 2,
          witnessedBy: state.witnesses);
      state = await reader().read(seed);
      expect((state.generation, state.tip.sn, state.fromItsOwnRecord),
          (1, rot.sn, true));
      final ixn = await m.interact(seed,
          aid: state.aid,
          generation: state.generation,
          afterSn: state.tip.sn,
          afterDigest: state.tip.digest,
          anchors: anchor,
          witnessedBy: state.witnesses);

      await TheIdentityThisDeviceHolds().forgetTheTip();
      state = await reader().read(seed);
      expect(state.fromItsOwnRecord, isFalse);
      expect((state.generation, state.tip.sn, state.tip.digest),
          (1, ixn.sn, ixn.digest));
      expect(state.establishment.digest, rot.digest);
      expect(state.corroborated, isTrue);
      expect(state.witnesses.witnesses, [w1.aid, w2.aid, w3.aid]);
      expect(
          reads.reads.where(
              (p) => p.startsWith('/api/identity') || p.startsWith('/api/kel')),
          isEmpty,
          reason: 'only public routes were read: ${reads.reads}');
      expect(reads.reads, contains('/public/oobi/${state.aid}'));
    });

    test(
        'a rotation the core says it added and keeps to itself gets no fork '
        'signed after it', () async {
      final m = makes();
      final founded =
          await m.found(seed, witnesses: [w1.aid, w2.aid, w3.aid], toad: 2);
      final set = WitnessSet([w1.aid, w2.aid, w3.aid], 2);
      for (final w in [w1, w2, w3]) {
        w.offline = true;
      }
      core.client.answerTheNextCommit = (201, '');
      await m.rotate(seed,
          aid: founded.aid,
          generation: 0,
          afterSn: 0,
          afterDigest: founded.digest,
          toad: 2,
          witnessedBy: set);
      for (final w in [w1, w2, w3]) {
        w.offline = false;
      }
      await TheIdentityThisDeviceHolds().forgetTheTip();
      await expectLater(
          reader().read(seed), throwsA(isA<TheCopiesAreBehindThisDevice>()));
    });

    test('two copies that differ at a rotation stop signing', () async {
      final m = makes();
      final founded =
          await m.found(seed, witnesses: [w1.aid, w2.aid, w3.aid], toad: 2);
      final set = WitnessSet([w1.aid, w2.aid, w3.aid], 2);
      // Another device with this phrase rotated at the same place, anchoring
      // something, and one witness took its rotation first.
      final rival = await _rotationOf(
          core, km, seed, founded.aid, (sn: 0, digest: founded.digest), anchor);
      await w3.hold(founded.aid, rival);
      await m.rotate(seed,
          aid: founded.aid,
          generation: 0,
          afterSn: 0,
          afterDigest: founded.digest,
          toad: 2,
          witnessedBy: set);
      await TheIdentityThisDeviceHolds().forgetTheTip();
      await expectLater(
          reader().read(seed),
          throwsA(
              isA<TheLogHasTwoHistories>().having((e) => e.sn, 'place', 1)));
    });
  });
}

/// A rotation of [aid] after [after] revealing this phrase's key 1, anchoring
/// [anchors], prepared by [core] and signed.
Future<SignedCopy> _rotationOf(ACore core, KeyMath km, Uint8List seed,
    String aid, Place after, List<Object?> anchors) async {
  final pq = KeyManager.slip10Ed25519(seed, KeyPaths.postQuantum(1));
  final res = await http.post(Uri.parse('${core.base}/api/events/prepare'),
      headers: const {
        'Content-Type': 'application/json',
        'X-Local-Owner-Secret': ownerSecret
      },
      body: jsonEncode({
        'aid': aid,
        't': 'rot',
        'k': [KeyManager.keyAt(seed, 1).publicKeyEncoded],
        'kt': '1',
        'n': [
          await km.nextKeyDigest(KeyManager.keyAt(seed, 2).publicKeyEncoded),
          (await km.postQuantumNext(pq)).digest
        ],
        'nt': '1',
        'a': anchors,
        'br': [],
        'ba': [],
        'bt': '2',
        'after': {'s': after.sn.toRadixString(16), 'd': after.digest},
      }));
  final raw = (jsonDecode(res.body) as Map)['raw_b64'] as String;
  final sig = ed.sign(ed.newKeyFromSeed(KeyManager.signingSeed(seed, index: 1)),
      base64Decode(raw));
  return SignedCopy(
      raw, [await cesrEncodeSignature(core.client, core.base, sig)]);
}
