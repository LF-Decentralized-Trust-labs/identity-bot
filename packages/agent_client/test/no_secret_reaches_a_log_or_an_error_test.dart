import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/local_core_keri_service.dart';
import 'package:agent_client/services/owner_signing_client.dart';
import 'package:agent_client/services/the_key_state_this_device_reads.dart';
import 'package:http/http.dart' as http;
import 'package:agent_client/services/recovering_this_identity.dart';
import 'package:agent_client/services/secure_key_store.dart';
import 'package:agent_client/services/the_key_events_this_device_makes.dart'
    show KeyPaths;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

import 'support/a_core_that_misleads.dart';
import 'support/a_witness.dart';
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
    // Witnessed, as an identity the app founds is: an identity no witness
    // holds is not recovered from its core's copy alone.
    final w1 = await AWitness.start(km);
    final w2 = await AWitness.start(km);
    addTearDown(w1.close);
    addTearDown(w2.close);
    final core = await anotherCore(bin, km, witnesses: [w1, w2]);
    final other = await anotherCore(bin, km);
    addTearDown(core.close);
    addTearDown(other.close);
    final printed = StringBuffer();
    final errors = <String>[];
    final ownerSignatures = <String>[];
    final child =
        KeyManager.signingSeed(Bip39.mnemonicToSeed(old.split(' ')), index: 0);
    final shortSeedHex = [
      for (final b in child.sublist(0, 31)) b.toRadixString(16).padLeft(2, '0')
    ].join();

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
      // Owner-signed requests, each signature recorded so the logs can be
      // searched for it.
      final owner = ownerKeyFromThePhrase(
          () async => old.split(' '),
          (String m) => Bip39.mnemonicToSeed(m.split(' ')),
          TheKeyStateThisDeviceReads(core.client, km, core.base));
      final signing = OwnerSigningClient(
          agentOrigin: core.base,
          ownerKey: owner.ownerKey,
          onStaleKeyState: owner.onStaleKeyState,
          inner: _RecordsOwnerSignatures(core.client, ownerSignatures));
      await each(
          () async => signing.get(Uri.parse('${core.base}/api/identity')));
      // Issuing a credential, which the app has the core build, anchors in an
      // interaction it signs, and has the core keep.
      await each(() async =>
          keri.issueCredential(claims: {'a': 'b'}, schemaSaid: 'E'));
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
              witnessAddresses: {w1.aid: w1.base, w2.aid: w2.base},
              agentBase: core.base));
      // keymath refusing a request names nothing it was sent: a real child
      // seed one byte short.
      await each(() async => km.run('pq_next', {'seed_hex': shortSeedHex}));
    }, zoneSpecification: ZoneSpecification(print: (_, __, ___, line) {
      printed.writeln(line);
    }));

    // Two flows fail on purpose (the refused rotation, keymath refusing a
    // short seed); every other flow, the credential's issuing among them, ran
    // to the end. The identity is witnessed, and its witnesses hold no other
    // event where the core refused one, so the refusal is let go of and the
    // rotation after it is made.
    expect(errors, hasLength(2), reason: errors.join('\n---\n'));
    expect(ownerSignatures, isNotEmpty);
    // What the cores wrote is read once it has all arrived.
    await Future<void>.delayed(const Duration(milliseconds: 500));
    final everything = [
      ('printed', printed.toString()),
      ('errors', errors.join('\n')),
      ('the first core\'s logs', core.logs.toString()),
      ('the second core\'s logs', other.logs.toString()),
    ];
    for (final secret in [
      ..._secretsOf(old),
      ..._secretsOf(fresh),
      shortSeedHex,
      ...ownerSignatures,
    ]) {
      for (final (where, text) in everything) {
        expect(text.contains(secret), isFalse,
            reason: 'a secret reached $where');
      }
    }
    // The words in any form: a list, a JSON array, joined some other way.
    for (final phrase in [old, fresh]) {
      final words = phrase.split(' ').take(4).map(RegExp.escape).join(r'\W+');
      for (final (where, text) in everything) {
        expect(RegExp(words).hasMatch(text), isFalse,
            reason: 'the phrase\'s words reached $where');
      }
    }
    // The flows ran: the move and the recovery reached the second phrase.
    expect(await SecureKeyStore.loadMnemonic(), isNull,
        reason: 'the wiped device holds no phrase until it is given one');
  }, timeout: const Timeout(Duration(minutes: 3)));
}

/// A client recording every owner signature it sends.
class _RecordsOwnerSignatures extends http.BaseClient {
  _RecordsOwnerSignatures(this._inner, this.signatures);
  final http.Client _inner;
  final List<String> signatures;
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    final sig = request.headers['X-IA-Owner-Sig'];
    if (sig != null) signatures.add(sig);
    return _inner.send(request);
  }
}
