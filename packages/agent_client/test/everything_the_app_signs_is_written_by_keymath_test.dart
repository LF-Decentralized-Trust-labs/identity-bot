import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/local_core_keri_service.dart';
import 'package:agent_client/services/secure_key_store.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

import 'support/a_core_that_misleads.dart';
import 'support/a_signature_read_back.dart';
import 'support/the_core.dart';

// ADR-061: the device writes every signature it makes with the core's code
// compiled into it (keymath). The core is not asked to, and /api/cesr/encode
// is a route nothing in this package reads.
//
// Late signing (finishStrandedEvents) is covered where its events are made, in
// a_stored_event_is_signed_only_if_it_is_the_one_this_phrase_makes_test.dart,
// with the same route failing.
void main() {
  late String bin;
  late KeyMath km;
  const words =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  final cores = <ACore>[];

  setUpAll(() async {
    bin = await buildTheCore('keymath-signs-core', dev: true);
    km = await keyMathOf(bin);
  });

  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
  });

  tearDown(() async {
    for (final c in cores) {
      await c.close();
    }
    cores.clear();
  });

  test(
      'what keymath writes at place 0 is what /api/cesr/encode wrote, in the '
      'indexed code the core reads an unindexed one as', () async {
    final core = await anotherCore(bin, km);
    cores.add(core);
    final raw = Uint8List.fromList(List.generate(64, (i) => (i * 7 + 3) % 256));
    final res = await core.client.post(Uri.parse('${core.base}/api/cesr/encode'),
        headers: const {'Content-Type': 'application/json'},
        body: jsonEncode({'raw_sig_b64': base64Encode(raw)}));
    final fromTheCore = (jsonDecode(res.body) as Map)['cesr_sig'] as String;
    final written = await km.signatureByTheOnlyKey(raw);

    expect(fromTheCore, startsWith('0B'));
    expect(written, startsWith('AA'));
    // The two differ in the code alone: the same 64 bytes, the same length.
    expect(written.length, fromTheCore.length);
    expect(written.substring(2), fromTheCore.substring(2));
    expect(rawOfIndexedSignature(written), raw);
  });

  test(
      'a founding, a rotation, an interaction and a credential are signed with '
      'the core unable to encode a signature, and it takes every one', () async {
    final core = await anotherCore(bin, km);
    cores.add(core);
    core.client.failOn.add('/api/cesr/encode');
    await SecureKeyStore.saveMnemonic(words.split(' '));
    final keri = LocalCoreKeriService(
        baseUrl: core.base, client: core.client, keyMath: km);

    final aid = (await keri.inceptAid(name: 'me', code: words)).aid;
    await keri.rotateAid(name: aid);
    await keri.interactAid(name: aid, sealData: const [
      {'d': 'Esealed'}
    ]);
    await keri.issueCredential(
        claims: {'name': 'Ada'}, schemaSaid: 'Eschema', holderAid: 'Eholder');

    final kel = jsonDecode(
        (await core.client.get(Uri.parse('${core.base}/api/kel?name=$aid')))
            .body) as Map;
    expect(kel['signed'], everyElement(isTrue),
        reason: 'the core recorded a signature on every event');
    expect((kel['signed'] as List).length, greaterThanOrEqualTo(4));
    expect(core.client.visited, isNot(contains('POST /api/cesr/encode')));
  });

  test(
      'a signature handed back for a presentation is the unindexed form, not '
      'the indexed one a key event carries', () async {
    final core = await anotherCore(bin, km);
    cores.add(core);
    await SecureKeyStore.saveMnemonic(words.split(' '));
    final keri = LocalCoreKeriService(
        baseUrl: core.base, client: core.client, keyMath: km);
    final aid = (await keri.inceptAid(name: 'me', code: words)).aid;

    final issued = await keri.issueCredential(
        claims: {'name': 'Ada'}, schemaSaid: 'Eschema', holderAid: aid);
    expect(issued.cesrSignature, startsWith('AA'),
        reason: 'the anchoring interaction is a key event');
    final presented = await keri.presentCredential(
        acdcSaid: issued.acdcSaid, holderAid: aid, issuerAid: aid);
    expect(presented.cesrSignature, startsWith('0B'));
    // /api/credential/verify judges a presentation only when it is handed the
    // presentation body, which that route does not take; the check on the
    // signature's form is made on the engine, in
    // keriengine/a_presentation_signed_by_keymath_verifies_test.go.
    expect(presented.cesrSignature.length, 88);
  });
}
