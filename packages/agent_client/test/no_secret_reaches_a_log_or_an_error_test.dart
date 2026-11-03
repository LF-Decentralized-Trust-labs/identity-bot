import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/local_core_keri_service.dart';
import 'package:agent_client/services/recovering_this_identity.dart';
import 'package:agent_client/services/secure_key_store.dart';
import 'package:agent_client/services/the_key_events_this_device_makes.dart' show KeyPaths;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

import 'support/a_core_that_misleads.dart';
import 'support/the_core.dart';

/// Every secret a phrase gives: the words, the BIP39 seed, and the child
/// seeds of the first signing, post-quantum and messaging keys, each as
/// hexadecimal and as base64.
List<String> _secretsOf(String phrase) {
  final seed = Bip39.mnemonicToSeed(phrase.split(' '));
  final children = <Uint8List>[
    seed,
    for (var j = 0; j < 5; j++) KeyManager.signingSeed(seed, index: j),
    for (var g = 0; g < 4; g++)
      KeyManager.slip10Ed25519(seed, KeyPaths.postQuantum(g)),
    for (var g = 0; g < 4; g++)
      KeyManager.slip10Ed25519(seed, KeyPaths.messaging(g)),
  ];
  String hex(List<int> b) =>
      [for (final x in b) x.toRadixString(16).padLeft(2, '0')].join();
  return [
    phrase,
    for (final c in children) ...[
      hex(c),
      hex(c).toUpperCase(),
      base64Encode(c),
      base64Url.encode(c).replaceAll('=', ''),
    ],
  ];
}

void main() {
  late String bin;
  late KeyMath km;
  const old =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const fresh =
      'legal winner thank year wave sausage worth useful legal winner thank yellow';

  setUpAll(() async {
    bin = await buildTheCore('no-secret-core', dev: true);
    km = await keyMathOf(bin);
  });

  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
  });

  test(
      'nothing a phrase gives reaches what the app prints, any error it '
      'raises, or the core\'s logs, through every flow', () async {
    final core = await anotherCore(bin, km);
    final other = await anotherCore(bin, km);
    addTearDown(core.close);
    addTearDown(other.close);
    final printed = StringBuffer();
    final errors = <String>[];

    Future<void> each(Future<void> Function() flow) async {
      try {
        await flow();
      } catch (e, st) {
        errors.add('$e\n$st');
      }
    }

    await runZoned(() async {
      await SecureKeyStore.saveMnemonic(old.split(' '));
      final keri = LocalCoreKeriService(
          baseUrl: core.base, client: core.client, keyMath: km);
      late String aid;
      await each(() async {
        aid = (await keri.inceptAid(name: 'me', code: old)).aid;
      });
      await each(() async => keri.rotateAid(name: aid));
      await each(() async => keri.interactAid(name: aid, sealData: const [
            {
              'i': 'EAnchoredAnchoredAnchoredAnchoredAnchored12',
              's': '0',
              'd': 'EAnchoredAnchoredAnchoredAnchoredAnchored12'
            }
          ]));
      await each(() async => keri.signPayload(name: aid, data: [1, 2, 3]));
      await each(() async => keri.replaceMessagingKeys());
      await each(() async => keri.moveToANewPhrase(words: fresh.split(' ')));
      // A refusal, so an error's text is read too; the refused rotation then
      // holds its place, so the next is refused as well.
      core.client.answerTheNextCommit = (403, 'not_authorised');
      await each(() async => keri.rotateAid(name: aid));
      await each(() async => keri.rotateAid(name: aid));
      // A wiped device recovers from the new phrase.
      FlutterSecureStorage.setMockInitialValues({});
      await each(() async =>
          RecoveringThisIdentity(other.client, other.base, km).recover(
              Bip39.mnemonicToSeed(fresh.split(' ')),
              aid: aid,
              witnessAddresses: const {},
              agentBase: core.base));
      // keymath refusing a request names nothing it was sent.
      await each(() async => km.run('pq_next', {'seed_hex': 'zz'}));
    }, zoneSpecification: ZoneSpecification(print: (_, __, ___, line) {
      printed.writeln(line);
    }));

    // Three flows fail on purpose (the refused rotation, the one after it,
    // keymath refusing a malformed seed); every other flow ran to the end.
    expect(errors, hasLength(3), reason: errors.join('\n---\n'));
    final everything = [
      ('printed', printed.toString()),
      ('errors', errors.join('\n')),
      ('the first core\'s logs', core.logs.toString()),
      ('the second core\'s logs', other.logs.toString()),
    ];
    for (final secret in [..._secretsOf(old), ..._secretsOf(fresh)]) {
      for (final (where, text) in everything) {
        expect(text.contains(secret), isFalse,
            reason: 'a secret of the phrase reached $where');
      }
    }
    // The flows ran: the move and the recovery reached the second phrase.
    expect(await SecureKeyStore.loadMnemonic(), isNull,
        reason: 'the wiped device holds no phrase until it is given one');
  });
}
