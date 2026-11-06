import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/local_core_keri_service.dart';
import 'package:agent_client/services/secure_key_store.dart';
import 'package:agent_client/services/the_event_this_device_expects.dart';
import 'package:agent_client/services/the_identity_this_device_holds.dart';
import 'package:agent_client/services/the_key_events_this_device_makes.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

import 'support/a_core_that_misleads.dart';
import 'support/the_core.dart';

/// Moving to a new phrase (ADR-061 section 10) from stage two (section 6),
/// against a core built with the `kerigo_pqtest` tag: both of the old phrase's
/// keys reveal and sign step 1, and both of the new phrase's reveal and sign
/// step 2.
void main() {
  // Each post-quantum signature and key is made by a call to the core's key
  // arithmetic, so a move takes longer than the default.
  const slow = Timeout(Duration(minutes: 3));
  late String bin;
  late KeyMath km;
  late ACore core;
  const old =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const fresh =
      'legal winner thank year wave sausage worth useful legal winner thank yellow';
  final oldSeed = Bip39.mnemonicToSeed(old.split(' '));
  final newSeed = Bip39.mnemonicToSeed(fresh.split(' '));

  setUpAll(() async {
    bin = await buildTheCore('stage-two-phrase-move-core',
        dev: true, tags: const ['kerigo_pqtest']);
    km = await keyMathOf(bin);
  });

  setUp(() async {
    FlutterSecureStorage.setMockInitialValues({});
    SecureKeyStore.holdPhraseWith(InMemoryPhraseHolder());
    SharedPreferences.setMockInitialValues({});
    PostQuantumCodes.useAssignedCodesInATest(true);
    core = await anotherCore(bin, km);
  });

  tearDown(() async {
    PostQuantumCodes.useAssignedCodesInATest(false);
    await core.close();
  });

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

  Future<String> pqVerkey(Uint8List seed, int g) async =>
      (await km.postQuantumNext(
              KeyManager.slip10Ed25519(seed, KeyPaths.postQuantum(g))))
          .verkey;
  Future<String> pqDigest(Uint8List seed, int g) async =>
      (await km.postQuantumNext(
              KeyManager.slip10Ed25519(seed, KeyPaths.postQuantum(g))))
          .digest;

  /// An identity founded on the old phrase and rotated to stage two.
  Future<String> aStageTwoIdentity() async {
    await SecureKeyStore.saveMnemonic(old.split(' '));
    final founded = await service().inceptAid(name: 'me', code: old);
    final h = await TheIdentityThisDeviceHolds().read();
    await core.makesReadingTheKeyState(oldSeed).rotateToStageTwo(oldSeed,
        aid: founded.aid,
        generation: 0,
        afterSn: h!.tip!.sn,
        afterDigest: h.tip!.digest,
        reCommitWitnessed: true);
    return founded.aid;
  }

  Future<void> expectTheMoveFromStageTwo(String aid) async {
    final log = await kel(aid);
    expect([for (final e in log) e['t']], ['icp', 'rot', 'rot', 'rot', 'ixn']);
    // Step 1: the old phrase's classical key 2 and post-quantum key 1, both
    // needed, committing to the new phrase's classical key 1 and
    // post-quantum generation 0.
    expect(log[2]['k'], [
      KeyManager.keyAt(oldSeed, 2).publicKeyEncoded,
      await pqVerkey(oldSeed, 1)
    ]);
    expect([log[2]['kt'], log[2]['nt']], ['2', '2']);
    expect(log[2]['n'], [
      await km.nextKeyDigest(KeyManager.keyAt(newSeed, 1).publicKeyEncoded),
      await pqDigest(newSeed, 0)
    ]);
    // Step 2: the new phrase's classical key 1 and post-quantum key 0.
    expect(log[3]['k'], [
      KeyManager.keyAt(newSeed, 1).publicKeyEncoded,
      await pqVerkey(newSeed, 0)
    ]);
    expect([log[3]['kt'], log[3]['nt']], ['2', '2']);
    expect(await SecureKeyStore.loadMnemonic(), fresh.split(' '));
    expect(await SecureKeyStore.loadPhraseMovingTo(), isNull);
  }

  test(
      'an identity at stage two moves to a new phrase with both keys of each '
      'phrase, and signs with the new phrase after', () async {
    final aid = await aStageTwoIdentity();
    await service().moveToANewPhrase(words: fresh.split(' '));
    await expectTheMoveFromStageTwo(aid);
    // Signed by both of the new phrase's keys: an interaction needs both.
    await service().interactAid(name: aid, sealData: const [
      {
        'i': 'EAnchoredAnchoredAnchoredAnchoredAnchored12',
        's': '0',
        'd': 'EAnchoredAnchoredAnchoredAnchoredAnchored12'
      }
    ]);
    expect(await kel(aid), hasLength(6));
  }, timeout: slow);

  test(
      'a move from stage two whose first rotation\'s answer was lost is '
      'finished after a restart, with both steps in the log once', () async {
    final aid = await aStageTwoIdentity();
    core.client.loseTheAnswerToCommitsAfter = 0;
    await expectLater(service().moveToANewPhrase(words: fresh.split(' ')),
        throwsA(isA<http.ClientException>()));
    expect(await SecureKeyStore.loadPhraseMovingTo(), fresh.split(' '));
    expect(await SecureKeyStore.loadMnemonic(), old.split(' '));

    // A restart: a new service, nothing but what was stored.
    await service().finishMovingToANewPhrase();
    await expectTheMoveFromStageTwo(aid);
  }, timeout: slow);

  test(
      'a move from stage two whose second rotation\'s answer was lost is '
      'finished after a restart, with that rotation in the log once', () async {
    final aid = await aStageTwoIdentity();
    core.client.loseTheAnswerToCommitsAfter = 1;
    await expectLater(service().moveToANewPhrase(words: fresh.split(' ')),
        throwsA(isA<http.ClientException>()));
    expect(await SecureKeyStore.loadMnemonic(), old.split(' '));

    await service().finishMovingToANewPhrase();
    await expectTheMoveFromStageTwo(aid);
  }, timeout: slow);

  test(
      'a core that refuses the first rotation at prepare leaves nothing kept as '
      'the phrase moved to, and the identity still signs', () async {
    final aid = await aStageTwoIdentity();
    // Asked for as a classical-only rotation, which the core refuses at
    // prepare for an identity at stage two (422 not_committed).
    core.client.alterThePrepare = (b) => b['t'] == 'rot'
        ? {
            ...b,
            'k': [(b['k'] as List).first],
            'kt': '1',
            'n': [(b['n'] as List).first],
            'nt': '1'
          }
        : null;
    await expectLater(
        service().moveToANewPhrase(words: fresh.split(' ')),
        throwsA(isA<KeyEventRefused>()
            .having((e) => e.code, 'code', 'not_committed')));
    core.client.alterThePrepare = null;
    expect(await SecureKeyStore.loadPhraseMovingTo(), isNull,
        reason: 'the move was never started, so nothing waits to be finished');
    expect(await SecureKeyStore.loadMnemonic(), old.split(' '));

    final before = (await kel(aid)).length;
    await service().interactAid(name: aid, sealData: const [
      {
        'i': 'EAnchoredAnchoredAnchoredAnchoredAnchored12',
        's': '0',
        'd': 'EAnchoredAnchoredAnchoredAnchoredAnchored12'
      }
    ]);
    expect(await kel(aid), hasLength(before + 1),
        reason: 'the identity signed after the refusal');
  }, timeout: slow);

  test(
      'a core that alters step 1 to commit to another post-quantum digest is '
      'caught before the new phrase is kept or anything is signed', () async {
    final aid = await aStageTwoIdentity();
    final other = await pqDigest(oldSeed, 5);
    // Only n[1] differs: the classical commitment is the one expected.
    core.client.alterThePrepare = (b) => b['t'] == 'rot'
        ? {
            ...b,
            'n': [(b['n'] as List).first, other]
          }
        : null;
    final commitsBefore = core.client.commits;
    await expectLater(service().moveToANewPhrase(words: fresh.split(' ')),
        throwsA(isA<NotTheEventExpected>()));
    core.client.alterThePrepare = null;
    expect(core.client.commits - commitsBefore, 0,
        reason: 'a step 1 that is not the one expected was sent to the core');
    expect(await SecureKeyStore.loadPhraseMovingTo(), isNull,
        reason: 'the new phrase was kept before step 1 was checked');
    expect(await SecureKeyStore.loadMnemonic(), old.split(' '));

    final before = (await kel(aid)).length;
    await service().interactAid(name: aid, sealData: const [
      {
        'i': 'EAnchoredAnchoredAnchoredAnchoredAnchored12',
        's': '0',
        'd': 'EAnchoredAnchoredAnchoredAnchoredAnchored12'
      }
    ]);
    expect(await kel(aid), hasLength(before + 1),
        reason: 'the identity could not sign after the refusal');
  }, timeout: slow);
}
