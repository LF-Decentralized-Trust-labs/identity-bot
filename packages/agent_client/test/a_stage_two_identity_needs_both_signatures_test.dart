import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/owner_signing_client.dart';
import 'package:agent_client/services/the_event_this_device_expects.dart';
import 'package:agent_client/services/the_events_this_device_signed.dart';
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
import 'support/a_key_math_that_counts.dart';
import 'support/the_core.dart';

/// Where an indexed signature says it counts: its code, its index, and the
/// prior-next place (null for a current-only code, which opens no commitment).
({String code, int index, int? ondex}) placesOf(String qb64) {
  const alphabet =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  int at(String chars) =>
      chars.split('').fold(0, (n, c) => n * 64 + alphabet.indexOf(c));
  if (qb64.startsWith('3Z')) {
    return (
      code: '3Z',
      index: at(qb64.substring(2, 5)),
      ondex: at(qb64.substring(5, 8))
    );
  }
  if (qb64.startsWith('3Y')) {
    return (code: '3Y', index: at(qb64.substring(2, 5)), ondex: null);
  }
  if (qb64.startsWith('A')) {
    return (
      code: 'A',
      index: at(qb64.substring(1, 2)),
      ondex: at(qb64.substring(1, 2))
    );
  }
  if (qb64.startsWith('B')) {
    return (code: 'B', index: at(qb64.substring(1, 2)), ondex: null);
  }
  throw ArgumentError('an indexed signature this test does not read: $qb64');
}

/// Stage two of a hybrid identity (ADR-061 section 6), against a core built
/// with the `kerigo_pqtest` tag, the only build that reads a post-quantum key.
/// The setting that allows it is off everywhere else.
void main() {
  late String bin;
  late KeyMath km;
  late ACore core;
  final seed = Bip39.mnemonicToSeed(
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
          .split(' '));
  Map<String, String> anchorOf(String name) => {
        'i': 'E${name}Anchored${'A' * 30}'.substring(0, 44),
        's': '0',
        'd': 'E${name}Anchored${'A' * 30}'.substring(0, 44)
      };

  setUpAll(() async {
    bin = await buildTheCore('stage-two-core',
        dev: true, tags: const ['kerigo_pqtest']);
    km = await keyMathOf(bin);
  });

  setUp(() async {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
    PostQuantumCodes.useAssignedCodesInATest(true);
    core = await anotherCore(bin, km);
  });

  tearDown(() async {
    PostQuantumCodes.useAssignedCodesInATest(false);
    await core.close();
  });

  Future<String> pqVerkey(int g) async => (await km.postQuantumNext(
          KeyManager.slip10Ed25519(seed, KeyPaths.postQuantum(g))))
      .verkey;
  Future<String> pqDigest(int g) async => (await km.postQuantumNext(
          KeyManager.slip10Ed25519(seed, KeyPaths.postQuantum(g))))
      .digest;
  Future<Map<String, Object?>> fieldsOf(Committed c) async => {
        for (final f in (await km.parseEvent(base64Decode(c.bytesB64))).fields)
          f.name: f.value
      };

  test(
      'a stage-two rotation commits with both signatures, and every event '
      'after it, an interaction or a rotation, needs both, whether or not the '
      'device restarted', () async {
    final founded = await core.makesReadingTheKeyState(seed).found(seed);
    final aid = founded.aid;

    final two = await core.makesReadingTheKeyState(seed).rotateToStageTwo(seed,
        aid: aid,
        generation: 0,
        afterSn: 0,
        afterDigest: founded.digest,
        reCommitWitnessed: true);
    expect(two.status, 'recorded');
    final fields = await fieldsOf(two);
    expect(fields['kt'], '2');
    expect(fields['nt'], '2');
    expect(fields['k'],
        [KeyManager.keyAt(seed, 1).publicKeyEncoded, await pqVerkey(0)]);
    expect(fields['n'], [
      await km.nextKeyDigest(KeyManager.keyAt(seed, 2).publicKeyEncoded),
      await pqDigest(1)
    ]);
    // A rotation's signatures each open the place of their own number in the
    // prior commitment: the Ed25519 key at index 0 opening prior-next 0, the
    // post-quantum key at index 1 opening prior-next 1.
    expect(two.signatures, hasLength(2));
    expect(placesOf(two.signatures[0]), (code: 'A', index: 0, ondex: 0));
    expect(placesOf(two.signatures[1]), (code: '3Z', index: 1, ondex: 1));
    expect(two.signatures[1], hasLength(4420));

    // The interaction opens no commitment, so each signature is current-only:
    // B at index 0 for the Ed25519 key, 3Y at index 1 for the post-quantum
    // key. The stage is read from the key state, never given.
    final both = await core.makesReadingTheKeyState(seed).interact(seed,
        aid: aid,
        generation: 1,
        afterSn: 1,
        afterDigest: two.digest,
        anchors: [anchorOf('First')]);
    expect(both.sn, 2);
    expect(both.status, 'recorded');
    expect(both.signatures, hasLength(2));
    expect(placesOf(both.signatures[0]), (code: 'B', index: 0, ondex: null));
    expect(placesOf(both.signatures[1]), (code: '3Y', index: 1, ondex: null));

    // Signed by the Ed25519 key alone and indexed, the core does not add it:
    // right, and too few, it holds it for the other key.
    final headers = {
      'Content-Type': 'application/json',
      'X-Local-Owner-Secret': ownerSecret
    };
    final prepared = jsonDecode(
        (await http.post(Uri.parse('${core.base}/api/events/prepare'),
                headers: headers,
                body: jsonEncode({
                  'aid': aid,
                  't': 'ixn',
                  'a': [anchorOf('Alone')],
                  'after': {'s': '2', 'd': both.digest},
                })))
            .body) as Map<String, dynamic>;
    final raw = base64Decode(prepared['raw_b64'] as String);
    final key = ed.newKeyFromSeed(KeyManager.signingSeed(seed, index: 1));
    final aloneSig = await km.indexEd25519Signature(ed.sign(key, raw),
        index: 0, currentOnly: true);
    final commit = await http.post(Uri.parse('${core.base}/api/events/commit'),
        headers: headers,
        body: jsonEncode({
          'raw_b64': prepared['raw_b64'],
          'sigs': [aloneSig]
        }));
    expect(commit.statusCode, 202, reason: commit.body);
    expect(jsonDecode(commit.body)['status'], 'waiting_for_signatures');
    Future<String> theLog() async =>
        (await http.get(Uri.parse('${core.base}/api/kel?name=$aid'),
                headers: {'X-Local-Owner-Secret': ownerSecret}))
            .body;
    expect(await theLog(), isNot(contains((await km.parseEvent(raw)).d)),
        reason: 'the core added an interaction only one key signed');

    // A restart: a new maker reads the stage again from what the device kept,
    // and signs with both keys without being told the identity is at stage two.
    final after = await core.makesReadingTheKeyState(seed).interact(seed,
        aid: aid,
        generation: 1,
        afterSn: 2,
        afterDigest: both.digest,
        anchors: [anchorOf('Second')]);
    expect(after.status, 'recorded');
    expect(after.signatures, hasLength(2));

    // A rotation after stage two reveals both keys and commits to both again
    // (kt and nt "2"), and both sign it.
    final rotated = await core.makesReadingTheKeyState(seed).rotate(seed,
        aid: aid, generation: 1, afterSn: 3, afterDigest: after.digest);
    expect(rotated.status, 'recorded');
    final next = await fieldsOf(rotated);
    expect((next['kt'], next['nt']), ('2', '2'));
    expect(next['k'],
        [KeyManager.keyAt(seed, 2).publicKeyEncoded, await pqVerkey(1)]);
    expect(next['n'], [
      await km.nextKeyDigest(KeyManager.keyAt(seed, 3).publicKeyEncoded),
      await pqDigest(2)
    ]);
    expect(placesOf(rotated.signatures[0]), (code: 'A', index: 0, ondex: 0));
    expect(placesOf(rotated.signatures[1]), (code: '3Z', index: 1, ondex: 1));

    // And the interaction after that one is signed by the keys it named.
    final last = await core.makesReadingTheKeyState(seed).interact(seed,
        aid: aid,
        generation: 2,
        afterSn: 4,
        afterDigest: rotated.digest,
        anchors: [anchorOf('Third')]);
    expect(last.status, 'recorded');
    expect(last.signatures, hasLength(2));

    // A device that is not told the identity is past stage one signs with the
    // Ed25519 key alone. That is one of the two signatures the event needs,
    // written at place 0 as keymath writes it, so the core holds it for the
    // other and does not record it, and the device treats it as refused.
    await expectLater(
        TheKeyEventsThisDeviceMakes(core.client, core.base, km).interact(seed,
            aid: aid,
            generation: 2,
            afterSn: 5,
            afterDigest: last.digest,
            anchors: [anchorOf('Stage1')]),
        throwsA(isA<AnEventWasRefused>().having((e) => e.refusal.statusCode,
            'status', 202)));
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      'the post-quantum key in k must be the one this phrase derives, or '
      'nothing is signed', () async {
    final founded = await core.makesReadingTheKeyState(seed).found(seed);
    final counting = AKeyMathThatCounts(km);
    final makes = TheKeyEventsThisDeviceMakes(core.client, core.base, counting,
        readTheKeyState: (_) async => (
              tip: (sn: 1, digest: founded.digest),
              generation: 1,
              witnesses: WitnessSet.none,
              keys: [
                KeyManager.keyAt(seed, 1).publicKeyEncoded,
                // another phrase's post-quantum key
                await pqVerkeyOf(
                    km, KeyManager.slip10Ed25519(seed, KeyPaths.postQuantum(5)))
              ]
            ));
    await expectLater(
        makes.interact(seed,
            aid: founded.aid,
            generation: 1,
            afterSn: 1,
            afterDigest: founded.digest,
            anchors: [anchorOf('Wrong')]),
        throwsA(isA<ThePostQuantumKeyInForceIsNotThisPhrases>()));
    expect(counting.postQuantumSignatures, 0);
    expect(core.client.commits, 1, reason: 'only the founding was committed');
    expect(await TheEventsThisDeviceSigned().unfinished(founded.aid), isEmpty);
  });

  group('the check before signing covers the stage-two paths', () {
    /// Founds an identity and returns what the stage-two rotation needs.
    Future<Committed> founded(TheKeyEventsThisDeviceMakes makes) =>
        makes.found(seed);

    Future<void> neverSigned(
        String aid, AKeyMathThatCounts counting, int commitsBefore) async {
      expect(counting.postQuantumSignatures, 0,
          reason: 'the post-quantum key signed an event nobody checked');
      expect(await TheEventsThisDeviceSigned().unfinished(aid), isEmpty,
          reason: 'a place was reserved, which is done only to sign');
      expect(core.client.commits, commitsBefore,
          reason: 'a signed event reached the core');
    }

    for (final (name, alter)
        in <(String, Map<String, Object?>? Function(Map<String, Object?>))>[
      (
        'k',
        (b) => b['t'] == 'rot'
            ? {
                ...b,
                'k': [(b['k'] as List)[0], 'D${'B' * 43}']
              }
            : null
      ),
      ('kt', (b) => b['t'] == 'rot' ? {...b, 'kt': '1'} : null),
      (
        'n',
        (b) => b['t'] == 'rot'
            ? {
                ...b,
                'n': [(b['n'] as List)[0]],
                'nt': '1'
              }
            : null
      ),
      ('nt', (b) => b['t'] == 'rot' ? {...b, 'nt': '1'} : null),
    ]) {
      test(
          'a stage-two rotation the core prepares with another $name is '
          'refused before any key signs', () async {
        final counting = AKeyMathThatCounts(km);
        final makes = core.makesReadingTheKeyState(seed, keyMath: counting);
        final f = await founded(makes);
        final commits = core.client.commits;
        core.client.alterThePrepare = alter;
        await expectLater(
            makes.rotateToStageTwo(seed,
                aid: f.aid,
                generation: 0,
                afterSn: 0,
                afterDigest: f.digest,
                reCommitWitnessed: true),
            throwsA(isA<NotTheEventExpected>()));
        await neverSigned(f.aid, counting, commits);
      });
    }

    test(
        'a dual-signed interaction the core prepares as another event is '
        'refused before any key signs', () async {
      final counting = AKeyMathThatCounts(km);
      final makes = core.makesReadingTheKeyState(seed, keyMath: counting);
      final f = await founded(makes);
      final two = await makes.rotateToStageTwo(seed,
          aid: f.aid,
          generation: 0,
          afterSn: 0,
          afterDigest: f.digest,
          reCommitWitnessed: true);
      final signed = counting.postQuantumSignatures;
      final commits = core.client.commits;
      core.client.alterThePrepare = (b) => b['t'] == 'ixn'
          ? {
              ...b,
              'a': [anchorOf('Another')]
            }
          : null;
      await expectLater(
          makes.interact(seed,
              aid: f.aid,
              generation: 1,
              afterSn: 1,
              afterDigest: two.digest,
              anchors: [anchorOf('Asked')]),
          throwsA(isA<NotTheEventExpected>()));
      expect(counting.postQuantumSignatures, signed,
          reason: 'the post-quantum key signed an event nobody checked');
      expect(
          (await TheEventsThisDeviceSigned().unfinished(f.aid))
              .where((r) => r.sn == 2),
          isEmpty);
      expect(core.client.commits, commits);
    });
  });

  test(
      'this device\'s own record of the stage beats what the core and the '
      'copies say (ADR-061 section 9): both readers say stage one, the record '
      'says stage two, and the interaction is signed by both keys', () async {
    final makes = core.makesReadingTheKeyState(seed);
    final f = await makes.found(seed);
    final two = await makes.rotateToStageTwo(seed,
        aid: f.aid,
        generation: 0,
        afterSn: 0,
        afterDigest: f.digest,
        reCommitWitnessed: true);
    final record = await TheIdentityThisDeviceHolds().read();
    expect(record!.keysInForce, hasLength(2),
        reason: 'the record is of stage two');

    // Both readers say the identity is at stage one, at the generation the
    // record has: only the record can say otherwise.
    KeyStateNow stageOne() => (
          tip: (sn: 1, digest: two.digest),
          generation: 1,
          witnesses: WitnessSet.none,
          keys: [KeyManager.keyAt(seed, 1).publicKeyEncoded]
        );
    final misled = TheKeyEventsThisDeviceMakes(core.client, core.base, km,
        held: TheIdentityThisDeviceHolds(),
        readTheKeyState: (_) async => stageOne(),
        readTheKeysInForce: (_) async => stageOne());
    final both = await misled.interact(seed,
        aid: f.aid,
        generation: 1,
        afterSn: 1,
        afterDigest: two.digest,
        anchors: [anchorOf('Record')]);
    expect(both.status, 'recorded');
    expect(both.signatures, hasLength(2),
        reason: 'signed by the classical key alone, as the readers said');
  });

  test(
      'an owner at stage two signs a request with both keys, and a request the '
      'Ed25519 key alone signed is refused', () async {
    final makes = core.makesReadingTheKeyState(seed);
    final f = await makes.found(seed);
    await makes.rotateToStageTwo(seed,
        aid: f.aid,
        generation: 0,
        afterSn: 0,
        afterDigest: f.digest,
        reCommitWitnessed: true);

    final reader = TheKeyStateThisDeviceReads(core.client, km, core.base);
    final owner = ownerKeyFromThePhrase(
        () async => ['unused'], (_) => Uint8List.fromList(seed), reader,
        keyMath: km);
    OwnerSigningClient client({required bool withThePostQuantumKey}) =>
        OwnerSigningClient(
            agentOrigin: core.base,
            agentAid: f.aid,
            ownerKey: owner.ownerKey,
            postQuantumSeed:
                withThePostQuantumKey ? owner.postQuantumSeed : null,
            keyMath: km,
            inner: http.Client());
    final url = Uri.parse('${core.base}/api/kel?name=${f.aid}');
    final alone = await client(withThePostQuantumKey: false).get(url);
    expect(alone.statusCode, anyOf(401, 403), reason: alone.body);
    final both = await client(withThePostQuantumKey: true).get(url);
    expect(both.statusCode, 200, reason: both.body);
  });
}

Future<String> pqVerkeyOf(KeyMath km, Uint8List pqSeed) async =>
    (await km.postQuantumNext(pqSeed)).verkey;
