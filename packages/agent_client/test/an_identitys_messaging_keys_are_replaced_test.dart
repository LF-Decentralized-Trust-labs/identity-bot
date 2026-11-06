import 'dart:convert';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/local_core_keri_service.dart';
import 'package:agent_client/services/recovering_this_identity.dart';
import 'package:agent_client/services/secure_key_store.dart';
import 'package:agent_client/services/the_identity_this_device_holds.dart';
import 'package:agent_client/services/the_key_events_this_device_makes.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

import 'support/a_core_that_misleads.dart';
import 'support/a_witness.dart';
import 'support/the_core.dart';

void main() {
  late String bin;
  late KeyMath km;
  late ACore core;
  late AWitness w1, w2;
  const phrase =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  final seed = Bip39.mnemonicToSeed(phrase.split(' '));

  setUpAll(() async {
    bin = await buildTheCore('messaging-keys-core', dev: true);
    km = await keyMathOf(bin);
    w1 = await AWitness.start(km);
    w2 = await AWitness.start(km);
  });

  tearDownAll(() async {
    await w1.close();
    await w2.close();
  });

  setUp(() async {
    FlutterSecureStorage.setMockInitialValues({});
    SecureKeyStore.holdPhraseWith(InMemoryPhraseHolder());
    SharedPreferences.setMockInitialValues({});
    w1.forgetAll();
    w2.forgetAll();
    // Witnessed, as an identity the app founds is: an identity no witness
    // holds is not recovered from its core's copy alone.
    core = await anotherCore(bin, km, witnesses: [w1, w2]);
  });

  tearDown(() => core.close());

  LocalCoreKeriService service([ACore? on]) => LocalCoreKeriService(
      baseUrl: (on ?? core).base, client: (on ?? core).client, keyMath: km);

  Future<List<Map<String, dynamic>>> kel(String aid, [ACore? on]) async {
    final res = await http.get(
        Uri.parse('${(on ?? core).base}/api/kel?name=$aid'),
        headers: const {'X-Local-Owner-Secret': ownerSecret});
    return [
      for (final e in (jsonDecode(res.body) as Map)['kel'] as List)
        Map<String, dynamic>.from(e as Map)
    ];
  }

  Future<Map<String, dynamic>> keyset(int g) =>
      km.messagingKeySet(KeyManager.slip10Ed25519(seed, KeyPaths.messaging(g)));

  test(
      'an identity\'s messaging keys are replaced by its phrase\'s next '
      'generation, anchored in an interaction, and a wiped device recovers '
      'onto that generation', timeout: const Timeout(Duration(minutes: 3)),
      () async {
    await SecureKeyStore.saveMnemonic(phrase.split(' '));
    final founded = await service().inceptAid(name: 'me', code: phrase);
    expect(await service().replaceMessagingKeys(), 1);
    final log = await kel(founded.aid);
    expect(log.last['t'], 'ixn');
    expect(jsonEncode(log.last['a']), jsonEncode([await keyset(1)]),
        reason: 'the latest anchor is the phrase\'s next keyset');

    // A second replacement moves on to the next generation again.
    expect(await service().replaceMessagingKeys(), 2);

    // Wiped, and recovered onto a new core from the old one's copy: the
    // messaging keys are the last ones anchored, and the new core takes their
    // seed.
    FlutterSecureStorage.setMockInitialValues({});
    SecureKeyStore.holdPhraseWith(InMemoryPhraseHolder());
    final other = await anotherCore(bin, km);
    addTearDown(other.close);
    final recovered = await RecoveringThisIdentity(other.client, other.base, km)
        .recover(seed,
            aid: founded.aid,
            witnessAddresses: {w1.aid: w1.base, w2.aid: w2.base},
            agentBase: core.base);
    expect(recovered.messagingGeneration, 2);
    expect(recovered.messagingKeysToReplace, isFalse);
  });

  test(
      'an identity whose messaging keys are not its phrase\'s gets the phrase\'s '
      'first keyset, after which they are', () async {
    // Founded anchoring no keyset of this phrase's, as an identity founded
    // before the fixed branch is in effect.
    final pq = KeyManager.slip10Ed25519(seed, KeyPaths.postQuantum(0));
    final icp = await preparedAndSigned(core.client, core.base, core.km, seed, 0, {
      't': 'icp',
      'k': [KeyManager.keyAt(seed, 0).publicKeyEncoded],
      'kt': '1',
      'n': [
        await km.nextKeyDigest(KeyManager.keyAt(seed, 1).publicKeyEncoded),
        (await km.postQuantumNext(pq)).digest
      ],
      'nt': '1',
      'a': [],
    });
    await commitTo(core.base, icp.rawB64, icp.sigs);
    final aid = (await km.parseEvent(base64Decode(icp.rawB64))).i;
    await SecureKeyStore.saveMnemonic(phrase.split(' '));
    await TheIdentityThisDeviceHolds().holds(aid);

    expect(await service().replaceMessagingKeys(), 0);
    final log = await kel(aid);
    expect(jsonEncode(log.last['a']), jsonEncode([await keyset(0)]));
  });

  test(
      'an identity that names no witnesses is not recovered from its core\'s '
      'copy alone, and the device records nothing of it', () async {
    final unwitnessed = await anotherCore(bin, km);
    addTearDown(unwitnessed.close);
    await SecureKeyStore.saveMnemonic(phrase.split(' '));
    final founded = await LocalCoreKeriService(
            baseUrl: unwitnessed.base, client: unwitnessed.client, keyMath: km)
        .inceptAid(name: 'me', code: phrase);
    expect(founded.witnesses, isEmpty);

    FlutterSecureStorage.setMockInitialValues({});

    SecureKeyStore.holdPhraseWith(InMemoryPhraseHolder());
    final other = await anotherCore(bin, km);
    addTearDown(other.close);
    await expectLater(
        RecoveringThisIdentity(other.client, other.base, km).recover(seed,
            aid: founded.aid,
            witnessAddresses: const {},
            agentBase: unwitnessed.base),
        throwsA(isA<RecoveryStopped>()));
    expect(await TheIdentityThisDeviceHolds().read(), isNull);
  });

  test('a keyset the core reports differently is not anchored', () async {
    await SecureKeyStore.saveMnemonic(phrase.split(' '));
    final founded = await service().inceptAid(name: 'me', code: phrase);
    final before = await kel(founded.aid);
    // A core that answers with another keyset's anchor.
    final lying = _AnswersAnotherAnchor(core.client, await keyset(9));
    await expectLater(
        LocalCoreKeriService(baseUrl: core.base, client: lying, keyMath: km)
            .replaceMessagingKeys(),
        throwsStateError);
    expect(await kel(founded.aid), hasLength(before.length));
  });
}

/// A client whose core answers a messaging seed with [anchor], whatever it
/// was handed.
class _AnswersAnotherAnchor extends http.BaseClient {
  _AnswersAnotherAnchor(this._inner, this.anchor);
  final http.Client _inner;
  final Map<String, dynamic> anchor;
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final res = await _inner.send(request);
    if (request.url.path != '/api/keystore/messaging-seed') return res;
    await res.stream.drain<void>();
    return http.StreamedResponse(
        Stream.value(utf8.encode(jsonEncode({'anchor': anchor}))), 200);
  }
}
