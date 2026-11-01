import 'dart:convert';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/services/local_core_keri_service.dart';
import 'package:agent_client/services/secure_key_store.dart';
import 'package:agent_client/services/the_key_is_not_held_by_the_core.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

// What the core answers where it does not hold the identity's key, as its
// writeKeyNotHeldHere writes it.
const reason = "This identity's key is not held by this Identity Agent: it is on your device or in your app. "
    "Its key log can't be extended here (no rotation, interaction or credential issued) until the app "
    'signs each event before it is added.';

http.Response refused() => http.Response(jsonEncode({'error': 'key_not_held_here', 'details': reason}), 409);

void main() {
  test('the core\'s reason for refusing reaches the person, word for word', () async {
    // A phrase on this device, and a core that keeps the identity's key log
    // and refuses to add to it.
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
    final words = Bip39.generateMnemonic();
    await SecureKeyStore.saveMnemonic(words);
    final key0 = KeyManager.keyAt(Bip39.mnemonicToSeed(words), 0).publicKeyEncoded;
    final icp = {'v': 'KERI10JSON', 't': 'icp', 'd': 'Eicp', 'i': 'Eaid', 's': '0', 'k': [key0]};
    final keri = LocalCoreKeriService(
      baseUrl: 'http://core.test',
      client: MockClient((req) async {
        switch (req.url.path) {
          case '/api/identity':
            return http.Response(jsonEncode({'aid': 'Eaid'}), 200);
          case '/api/kel':
            return http.Response(
                jsonEncode({
                  'aid': 'Eaid',
                  'kel': [icp],
                  'raw_events_b64': [base64Encode(utf8.encode(jsonEncode(icp)))],
                  'signed': [true],
                }),
                200);
        }
        return refused();
      }),
    );
    Object? thrown;
    try {
      await keri.issueCredential(claims: {'role': 'engineer'}, schemaSaid: 'Eschema');
    } catch (e) {
      thrown = e;
    }
    expect(thrown, isA<KeyNotHeldByTheCore>());
    // What a screen shows is the exception as a string: the reason itself,
    // not a generic failure or a status code.
    expect(thrown.toString(), reason);
  });

  test('any other refusal still says what the core said', () {
    Object? thrown;
    try {
      refusedByTheCore(http.Response(jsonEncode({'error': 'something else'}), 500), 'Rotation failed');
    } catch (e) {
      thrown = e;
    }
    expect(thrown, isNot(isA<KeyNotHeldByTheCore>()));
    expect(thrown.toString(), contains('something else'));
  });
}
