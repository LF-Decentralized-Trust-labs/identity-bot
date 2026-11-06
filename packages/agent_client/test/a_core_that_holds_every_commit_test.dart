import 'dart:convert';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/local_core_keri_service.dart';
import 'package:agent_client/services/secure_key_store.dart';
import 'package:agent_client/services/the_events_this_device_signed.dart';
import 'package:agent_client/services/the_key_events_this_device_makes.dart';
import 'package:agent_client/services/the_witnesses_of_this_devices_events.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

import 'support/a_core_that_misleads.dart';
import 'support/a_witness.dart';
import 'support/the_core.dart';

/// A core that answers every commit `202 waiting_for_signatures` and adds
/// nothing. This device signs with every key an event needs, so an honest core
/// never says it: the event is treated like any answer that is not "recorded",
/// and the person is never left with a place nothing can release.
void main() {
  late String bin;
  late KeyMath km;
  late ACore core;
  late AWitness w1, w2;
  const phrase =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  final seed = Bip39.mnemonicToSeed(phrase.split(' '));
  final anchor = [
    {
      'i': 'EAnchoredAnchoredAnchoredAnchoredAnchored12',
      's': '0',
      'd': 'EAnchoredAnchoredAnchoredAnchoredAnchored12'
    }
  ];

  setUpAll(() async {
    bin = await buildTheCore('held-commit-core', dev: true);
    km = await keyMathOf(bin);
  });

  setUp(() async {
    FlutterSecureStorage.setMockInitialValues({});
    SecureKeyStore.holdPhraseWith(InMemoryPhraseHolder());
    SharedPreferences.setMockInitialValues({});
    core = await anotherCore(bin, km);
    w1 = await AWitness.start(km);
    w2 = await AWitness.start(km);
  });

  tearDown(() async {
    await core.close();
    await w1.close();
    await w2.close();
  });

  Future<List<String>> theLog(String aid) async {
    final res = await http.get(Uri.parse('${core.base}/api/kel?name=$aid'),
        headers: const {'X-Local-Owner-Secret': ownerSecret});
    return [
      for (final e in (jsonDecode(res.body) as Map)['kel'] as List)
        '${(e as Map)['d']}'
    ];
  }

  test(
      'an event the core holds for more signers goes to the witnesses and is '
      'the core\'s to account for, and committing it again adds it', () async {
    final witnesses = TheWitnessesOfThisDevicesEvents(
        http.Client(), km, KnownWitnesses({w1.aid: w1.base, w2.aid: w2.base}));
    final makes = core.makes(witnesses);
    final set = WitnessSet([w1.aid, w2.aid], 2);
    final founded = await makes.found(seed, witnesses: set.witnesses, toad: 2);

    core.client.holdEveryCommit = true;
    await expectLater(
        makes.interact(seed,
            aid: founded.aid,
            generation: 0,
            afterSn: 0,
            afterDigest: founded.digest,
            anchors: anchor,
            witnessedBy: set),
        throwsA(isA<TheCoreWithholdsThisEvent>()
            .having((e) => e.refusal.code, 'code', 'waiting_for_signatures')
            .having((e) => e.witnessed.enough, 'receipted', isTrue)));
    expect(await theLog(founded.aid), hasLength(1),
        reason: 'the core added nothing');
    final kept = await TheEventsThisDeviceSigned().unfinished(founded.aid);
    expect(kept.single.recorded, isFalse,
        reason: 'an event the core did not record is not marked recorded');

    // The core answers properly again: the kept event is committed as it was
    // signed, and is the identity's next event; nobody is stuck.
    core.client.holdEveryCommit = false;
    final done = await makes.finishSigned(founded.aid, witnessedBy: set);
    expect(done.single.status, 'recorded');
    expect(await theLog(founded.aid), hasLength(2));
  });

  test(
      'with no witness to ask, the held event is refused for good and the '
      'person can let it go, so the next event can be signed', () async {
    final makes = core.makes(TheWitnessesOfThisDevicesEvents(
        http.Client(), km, KnownWitnesses(const {})));
    final founded = await makes.found(seed);

    core.client.holdEveryCommit = true;
    await expectLater(
        makes.interact(seed,
            aid: founded.aid,
            generation: 0,
            afterSn: 0,
            afterDigest: founded.digest,
            anchors: anchor),
        throwsA(isA<AnEventWasRefused>()
            .having((e) => e.refusal.code, 'code', 'waiting_for_signatures')));
    expect(await makes.letGoOf(founded.aid, 1, withoutWitnesses: true),
        LetGo.released);

    core.client.holdEveryCommit = false;
    final next = await makes.interact(seed,
        aid: founded.aid,
        generation: 0,
        afterSn: 0,
        afterDigest: founded.digest,
        anchors: anchor);
    expect(next.status, 'recorded');
  });

  test('interactAid and rotateAid do not report a held event as done',
      () async {
    await SecureKeyStore.saveMnemonic(phrase.split(' '));
    LocalCoreKeriService service() => LocalCoreKeriService(
        baseUrl: core.base, client: core.client, keyMath: km);
    final founded = await service().inceptAid(name: 'me', code: phrase);

    core.client.holdEveryCommit = true;
    await expectLater(
        service().interactAid(
            name: founded.aid,
            sealData: anchor
                .map((a) => {for (final e in a.entries) e.key: '${e.value}'})
                .toList()),
        throwsA(isA<AnEventWasRefused>()));
    await expectLater(service().rotateAid(name: founded.aid),
        throwsA(isA<AnEventWasRefused>()));
    expect(await theLog(founded.aid), hasLength(1),
        reason: 'the founding is all the core holds');
  });
}
