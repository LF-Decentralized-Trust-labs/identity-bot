import 'dart:convert';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/local_core_keri_service.dart';
import 'package:agent_client/services/secure_key_store.dart';
import 'package:agent_client/services/the_identity_this_device_holds.dart';
import 'package:agent_client/services/the_events_this_device_signed.dart';
import 'package:agent_client/services/the_key_events_this_device_makes.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

import 'support/a_core_that_misleads.dart';
import 'support/the_core.dart';

void main() {
  late String bin;
  late KeyMath km;
  late ACore core;
  const old =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const fresh =
      'legal winner thank year wave sausage worth useful legal winner thank yellow';
  final oldSeed = Bip39.mnemonicToSeed(old.split(' '));
  final newSeed = Bip39.mnemonicToSeed(fresh.split(' '));
  const anchor = [
    {
      'i': 'EAnchoredAnchoredAnchoredAnchoredAnchored12',
      's': '0',
      'd': 'EAnchoredAnchoredAnchoredAnchoredAnchored12'
    }
  ];

  setUpAll(() async {
    bin = await buildTheCore('phrase-move-core', dev: true);
    km = await keyMathOf(bin);
  });

  setUp(() async {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
    core = await anotherCore(bin, km);
  });

  tearDown(() => core.close());

  LocalCoreKeriService service() => LocalCoreKeriService(
      baseUrl: core.base, client: core.client, keyMath: km);

  Future<List<Map<String, dynamic>>> kel(String aid) async {
    final res = await http.get(Uri.parse('${core.base}/api/kel?name=$aid'),
        headers: const {'X-Local-Owner-Secret': ownerSecret});
    return [
      for (final e in (jsonDecode(res.body) as Map)['kel'] as List)
        Map<String, dynamic>.from(e as Map)
    ];
  }

  /// An identity founded and rotated once on the old phrase.
  Future<String> anIdentity() async {
    await SecureKeyStore.saveMnemonic(old.split(' '));
    final keri = service();
    final founded = await keri.inceptAid(name: 'me', code: old);
    await keri.rotateAid(name: founded.aid);
    return founded.aid;
  }

  test(
      'an identity moves to a new phrase in two rotations, signs with the new '
      'phrase after, and the old phrase cannot rotate it again', () async {
    final aid = await anIdentity();
    final keri = service();
    final moved = await keri.moveToANewPhrase(words: fresh.split(' '));
    expect(moved.newPublicKey, KeyManager.keyAt(newSeed, 1).publicKeyEncoded);

    final log = await kel(aid);
    expect([for (final e in log) e['t']], ['icp', 'rot', 'rot', 'rot', 'ixn']);
    expect(log[2]['k'], [KeyManager.keyAt(oldSeed, 2).publicKeyEncoded],
        reason: 'step 1 reveals the old phrase\'s next key');
    expect((log[2]['n'] as List).first,
        await km.nextKeyDigest(KeyManager.keyAt(newSeed, 1).publicKeyEncoded),
        reason: 'and commits to the new phrase');
    expect(log[3]['k'], [KeyManager.keyAt(newSeed, 1).publicKeyEncoded]);
    // The messaging keys are replaced at once with the new phrase's, since
    // whoever holds the old phrase can derive the old ones.
    final keyset = await km.messagingKeySet(
        KeyManager.slip10Ed25519(newSeed, KeyPaths.messaging(0)));
    expect(jsonEncode(log[4]['a']), jsonEncode([keyset]));

    expect(await SecureKeyStore.loadMnemonic(), fresh.split(' '));
    expect(await SecureKeyStore.loadPhraseMovingTo(), isNull);
    final signed = await keri.signPayload(name: aid, data: [1, 2, 3]);
    expect(signed.publicKey, KeyManager.keyAt(newSeed, 1).publicKeyEncoded);

    // A holder of the old phrase cannot rotate the identity: its next key is
    // committed to nowhere.
    await expectLater(
        TheKeyEventsThisDeviceMakes(core.client, core.base, km).rotate(oldSeed,
            aid: aid, generation: 2, afterSn: 3, afterDigest: '${log[3]['d']}'),
        throwsA(isA<KeyEventRefused>()
            .having((e) => e.code, 'code', 'not_committed')));
  });

  test(
      'a move whose second rotation\'s answer was lost is finished, with that '
      'rotation committed once, and the new phrase put in force only then',
      () async {
    final aid = await anIdentity();
    final keri = service();
    // Commits so far: founding and rotation. Step 1 is the next; step 2's
    // answer is the one lost.
    core.client.loseTheAnswerToCommitsAfter = 1;
    await expectLater(keri.moveToANewPhrase(words: fresh.split(' ')),
        throwsA(isA<http.ClientException>()));
    expect(await SecureKeyStore.loadMnemonic(), old.split(' '),
        reason: 'the old phrase stays in force until the move is finished');
    expect(await SecureKeyStore.loadPhraseMovingTo(), fresh.split(' '));

    await service().finishMovingToANewPhrase();
    final log = await kel(aid);
    expect(log, hasLength(5), reason: 'step 2 is in the log once');
    expect(log[3]['k'], [KeyManager.keyAt(newSeed, 1).publicKeyEncoded]);
    expect(await SecureKeyStore.loadMnemonic(), fresh.split(' '));
    expect(await SecureKeyStore.loadPhraseMovingTo(), isNull);
  });

  test(
      'the second rotation supersedes an interaction a holder of the old phrase '
      'signed between the two', () async {
    final aid = await anIdentity();
    final h = await TheIdentityThisDeviceHolds().read();
    final makes = TheKeyEventsThisDeviceMakes(core.client, core.base, km,
        held: TheIdentityThisDeviceHolds());
    await SecureKeyStore.savePhraseMovingTo(fresh.split(' '));
    final step1 = await makes.moveToANewPhrase(oldSeed, newSeed,
        aid: aid,
        generation: 1,
        afterSn: h!.tip!.sn,
        afterDigest: h.tip!.digest);
    // The old phrase's key is still in force until step 2: its holder signs
    // an interaction.
    final theirs = await TheKeyEventsThisDeviceMakes(core.client, core.base, km)
        .interact(oldSeed,
            aid: aid,
            generation: 2,
            afterSn: step1.sn,
            afterDigest: step1.digest,
            anchors: anchor);
    expect((await kel(aid))[theirs.sn]['t'], 'ixn');

    await service().finishMovingToANewPhrase();
    final log = await kel(aid);
    expect(log, hasLength(step1.sn + 3));
    expect(log[step1.sn + 1]['t'], 'rot',
        reason: 'step 2 took the place of the old phrase\'s interaction');
    expect(log[step1.sn + 1]['p'], step1.digest);
    expect(await SecureKeyStore.loadMnemonic(), fresh.split(' '));
  });

  test(
      'a move to the phrase in force, or to a second phrase mid-move, is refused',
      () async {
    await anIdentity();
    final keri = service();
    await expectLater(
        keri.moveToANewPhrase(words: old.split(' ')), throwsArgumentError);
    await SecureKeyStore.savePhraseMovingTo(fresh.split(' '));
    await expectLater(
        keri.moveToANewPhrase(
            words:
                'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'.split(' ')),
        throwsStateError);
  });

  test(
      'a move whose first rotation never reached the log is finished the next '
      'time the identity signs, and nothing is signed with the old phrase '
      'meanwhile', () async {
    final aid = await anIdentity();
    final keri = service();
    core.client.answerTheNextCommit = (503, 'busy');
    await expectLater(keri.moveToANewPhrase(words: fresh.split(' ')),
        throwsA(isA<KeyEventRefused>()));
    expect(await kel(aid), hasLength(2), reason: 'step 1 is not in the log');

    final signed = await service().signPayload(name: aid, data: [1]);
    expect(signed.publicKey, KeyManager.keyAt(newSeed, 1).publicKeyEncoded,
        reason: 'the move was finished first, so the new phrase signed');
    expect(await kel(aid), hasLength(5));
    expect(await SecureKeyStore.loadMnemonic(), fresh.split(' '));
  });

  test('a move that stopped before anything was signed is finished from step 1',
      () async {
    final aid = await anIdentity();
    await SecureKeyStore.savePhraseMovingTo(fresh.split(' '));
    await service().finishMovingToANewPhrase();
    final log = await kel(aid);
    expect([for (final e in log) e['t']], ['icp', 'rot', 'rot', 'rot', 'ixn']);
    expect(log[3]['k'], [KeyManager.keyAt(newSeed, 1).publicKeyEncoded]);
  });

  test(
      'an interaction of this device\'s the core refused during the move is '
      'superseded by step 2 and never committed again', () async {
    final aid = await anIdentity();
    final h = await TheIdentityThisDeviceHolds().read();
    final makes = TheKeyEventsThisDeviceMakes(core.client, core.base, km,
        held: TheIdentityThisDeviceHolds());
    await SecureKeyStore.savePhraseMovingTo(fresh.split(' '));
    final step1 = await makes.moveToANewPhrase(oldSeed, newSeed,
        aid: aid,
        generation: 1,
        afterSn: h!.tip!.sn,
        afterDigest: h.tip!.digest);
    core.client.answerTheNextCommit = (403, 'not_authorised');
    await expectLater(
        makes.interact(oldSeed,
            aid: aid,
            generation: 2,
            afterSn: step1.sn,
            afterDigest: step1.digest,
            anchors: anchor),
        throwsA(isA<AnEventWasRefused>()));
    expect(await TheEventsThisDeviceSigned().unfinished(aid), hasLength(1));

    await service().finishMovingToANewPhrase();
    expect(await TheEventsThisDeviceSigned().unfinished(aid), isEmpty,
        reason: 'step 2 superseded the refused interaction, which is dead');
    expect((await kel(aid))[step1.sn + 1]['t'], 'rot');
  });

  test(
      'where somebody holding the old phrase moved the identity to keys of their '
      'own first, the move is dropped and the person is told why', () async {
    final aid = await anIdentity();
    final h = await TheIdentityThisDeviceHolds().read();
    final stranger = Bip39.mnemonicToSeed(
        'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'.split(' '));
    final theirs = await preparedAndSigned(core.client, core.base, oldSeed, 2, {
      'aid': aid,
      't': 'rot',
      'k': [KeyManager.keyAt(oldSeed, 2).publicKeyEncoded],
      'kt': '1',
      'n': [
        await km.nextKeyDigest(KeyManager.keyAt(stranger, 1).publicKeyEncoded)
      ],
      'nt': '1',
      'a': [],
      'br': [],
      'ba': [],
      'bt': '0',
      'after': {'s': h!.tip!.sn.toRadixString(16), 'd': h.tip!.digest},
    });
    await commitTo(core.base, theirs.rawB64, theirs.sigs);

    await expectLater(service().moveToANewPhrase(words: fresh.split(' ')),
        throwsA(isA<TheOldPhraseNoLongerControlsTheIdentity>()));
    expect(await SecureKeyStore.loadPhraseMovingTo(), isNull);
    expect(await SecureKeyStore.loadMnemonic(), old.split(' '));
  });
}
