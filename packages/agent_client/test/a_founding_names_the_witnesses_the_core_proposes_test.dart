import 'dart:convert';

import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/keri_service.dart';
import 'package:agent_client/services/local_core_keri_service.dart';
import 'package:agent_client/services/secure_key_store.dart';
import 'package:agent_client/services/the_identity_this_device_holds.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

import 'support/a_core_that_misleads.dart';
import 'support/a_witness.dart';
import 'support/the_core.dart';

/// An identity the app founds names the witnesses its core would have chosen,
/// each confirmed by its own signed answer (ADR-061 sections 3 and 9), not
/// none: a founding that names no witness has nothing to corroborate it, and
/// cannot be amended.
void main() {
  late String bin;
  late KeyMath km;
  late AWitness w1, w2;
  late ACore core;

  const phrase =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

  setUpAll(() async {
    bin = await buildTheCore('witnessed-founding-core', dev: true);
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
    SharedPreferences.setMockInitialValues({});
    w1.forgetAll();
    w2.forgetAll();
    await SecureKeyStore.saveMnemonic(phrase.split(' '));
  });

  tearDown(() => core.close());

  Future<Map<String, dynamic>> founding(String aid) async {
    final res = await http.get(Uri.parse('${core.base}/api/kel?name=$aid'),
        headers: const {'X-Local-Owner-Secret': ownerSecret});
    final log = (jsonDecode(res.body) as Map)['kel'] as List;
    return Map<String, dynamic>.from(log.first as Map);
  }

  Future<InceptionResult> found(List<AWitness> proposed) async {
    core = await anotherCore(bin, km, witnesses: proposed);
    return LocalCoreKeriService(
            baseUrl: core.base, client: core.client, keyMath: km)
        .inceptAid(name: 'me', code: phrase);
  }

  test(
      'a founding names the witnesses the core proposes, and the device\'s '
      'record holds where they are', () async {
    final done = await found([w1, w2]);
    expect(done.witnesses, unorderedEquals([w1.aid, w2.aid]));
    expect(done.witnessThreshold, 2);
    expect(done.unwitnessedBecause, isNull);

    final icp = await founding(done.aid);
    expect(List<String>.from(icp['b'] as List),
        unorderedEquals([w1.aid, w2.aid]));
    expect(icp['bt'], '2');

    final h = await TheIdentityThisDeviceHolds().read();
    expect(h!.witnessAddresses, {w1.aid: w1.base, w2.aid: w2.base});
    expect(h.witnesses, unorderedEquals([w1.aid, w2.aid]));
    expect(h.toad, 2);
    // The founding itself is the first event each holds.
    expect(w1.held[done.aid]!.first.rawB64, done.rawBytesB64);
    expect(w2.held[done.aid]!.first.rawB64, done.rawBytesB64);
  });

  test(
      'a proposed witness that does not answer is left out, and the threshold '
      'falls to the witnesses that remain', () async {
    w2.mute = true;
    final done = await found([w1, w2]);
    expect(done.witnesses, [w1.aid]);
    expect(done.witnessThreshold, 1);
    final icp = await founding(done.aid);
    expect(icp['b'], [w1.aid]);
    expect(icp['bt'], '1');
    final h = await TheIdentityThisDeviceHolds().read();
    expect(h!.witnessAddresses.keys, [w1.aid]);
  });

  test('a proposed witness that answers with another witness\'s key is left out',
      () async {
    w2.tipSignedByAnother = true;
    final done = await found([w1, w2]);
    expect(done.witnesses, [w1.aid]);
    final icp = await founding(done.aid);
    expect(icp['b'], [w1.aid]);
  });

  test('where none answers the founding names none, and says why', () async {
    w1.mute = true;
    w2.mute = true;
    final done = await found([w1, w2]);
    expect(done.witnesses, isEmpty);
    expect(done.unwitnessedBecause, contains('none of the 2 witnesses'));
    final icp = await founding(done.aid);
    expect(icp['b'], isEmpty);
    expect(icp['bt'], '0');
  });

  test('a core that proposes none gets a founding with none, and says why',
      () async {
    final done = await found(const []);
    expect(done.witnesses, isEmpty);
    expect(done.unwitnessedBecause, 'the core proposed no witnesses');
    final icp = await founding(done.aid);
    expect(icp['b'], isEmpty);
  });
}
