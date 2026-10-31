import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/services/local_core_keri_service.dart';
import 'package:agent_client/services/secure_key_store.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

// The raw 32 bytes behind a qb64 key with a one-character code.
List<int> rawOf(String qb64) => base64Url.decode('A${qb64.substring(1)}').sublist(1);

void main() {
  final words = Bip39.generateMnemonic();
  final rotationEvent = utf8.encode('{"t":"rot","s":"1"}');

  late Map<String, Map<String, dynamic>> sent;
  late LocalCoreKeriService keri;

  setUp(() async {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
    await SecureKeyStore.saveMnemonic(words);
    sent = {};
    keri = LocalCoreKeriService(
      baseUrl: 'http://core.test',
      client: MockClient((req) async {
        final body = jsonDecode(req.body) as Map<String, dynamic>;
        sent[req.url.path] = body;
        switch (req.url.path) {
          case '/api/inception':
          case '/api/rotation':
            return http.Response(
                jsonEncode({'aid': 'Eaid', 'raw_bytes_b64': base64Encode(rotationEvent)}), 200);
          case '/api/cesr/encode':
            return http.Response(jsonEncode({'cesr_sig': '0Bsig'}), 200);
          default:
            return http.Response('{}', 200);
        }
      }),
    );
  });

  test('a rotation names the key founding committed to, and that key signs it', () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    final committed = sent['/api/inception']!['next_public_key'] as String;

    await keri.rotateAid(name: 'me');
    final rotation = sent['/api/rotation']!;
    expect(rotation['new_public_key'], committed,
        reason: 'the new key must be the next key the founding event committed to');

    // The signature handed back for the rotation verifies under the key it names.
    final sig = base64Decode(sent['/api/cesr/encode']!['raw_sig_b64'] as String);
    final named = ed.PublicKey(rawOf(rotation['new_public_key'] as String));
    expect(ed.verify(named, Uint8List.fromList(rotationEvent), Uint8List.fromList(sig)), isTrue,
        reason: 'the key the rotation names must be the key that signs it');

    // And the rotation commits to the key after it, derived the same way.
    final seed = Bip39.mnemonicToSeed(words);
    expect(rotation['new_next_public_key'], KeyManager.keyAt(seed, 2).publicKeyEncoded);
    expect(rotation['new_next_public_key'], isNot(rotation['new_public_key']));
  });

  test('every key in the chain comes from signingSeed, hashed once', () {
    final seed = Bip39.mnemonicToSeed(words);
    final keys = KeyManager.generateKeysFromMnemonic(words);
    for (final (index, pair) in [(0, keys.signing), (1, keys.next)]) {
      final fromSeed = ed.public(ed.newKeyFromSeed(KeyManager.signingSeed(seed, index: index)));
      expect(pair.publicKey, fromSeed.bytes);
      expect(KeyManager.keyAt(seed, index).publicKey, fromSeed.bytes);
    }
    expect(KeyManager.signingSeed(seed), KeyManager.signingSeed(seed, index: 0));
    expect(() => KeyManager.signingSeed(seed, index: 256), throwsArgumentError);
  });

  test('a signature made as the identity reports the key that made it', () async {
    final data = utf8.encode('hello');
    final result = await keri.signPayload(name: 'me', data: data);
    final key = ed.PublicKey(rawOf(result.publicKey));
    expect(ed.verify(key, Uint8List.fromList(data), base64Decode(result.signature)), isTrue);
  });
}
