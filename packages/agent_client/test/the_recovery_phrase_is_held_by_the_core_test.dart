import 'dart:convert';

import 'package:agent_client/services/root_seed_handoff.dart';
import 'package:agent_client/services/secure_key_store.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

const _phrase =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const _core = 'http://127.0.0.1:5050';

/// A core, as far as the phrase routes go. [refuse] answers every route with the
/// root-seed refusal, as a production core does where it cannot wrap.
class _FakeCore {
  _FakeCore({this.refuse = false});
  final bool refuse;
  String? held;
  final seen = <String>[];

  MockClient get client => MockClient((req) async {
        seen.add('${req.method} ${req.url.path}');
        if (refuse) {
          return http.Response(
              jsonEncode({
                'error': 'an identity cannot be created on this computer',
                'details': 'its key protection is not proven usable',
                'code': 'root_seed_refused'
              }),
              412);
        }
        switch ('${req.method} ${req.url.path}') {
          case 'PUT /api/keystore/recovery-phrase':
            held = (jsonDecode(req.body) as Map)['phrase'] as String;
            return http.Response('{"held":true}', 201);
          case 'POST /api/keystore/recovery-phrase/open':
            return held == null
                ? http.Response('{"error":"none"}', 404)
                : http.Response(jsonEncode({'phrase': held}), 200);
          case 'GET /api/keystore/recovery-phrase':
            return http.Response(
                jsonEncode(held == null
                    ? {'held': false}
                    : {'held': true, 'protection': 'hardware-wrapped'}),
                200);
          case 'DELETE /api/keystore/recovery-phrase':
            held = null;
            return http.Response('{"held":false}', 200);
        }
        return http.Response('', 404);
      });
}

void main() {
  late FlutterSecureStorage legacy;
  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
    legacy = const FlutterSecureStorage();
  });
  tearDown(SecureKeyStore.holdPhraseInTheCore);

  test('saving the phrase puts it in the core and nowhere in the app\'s own storage', () async {
    final core = _FakeCore();
    SecureKeyStore.holdPhraseWith(CorePhraseHolder(baseUrl: _core, client: core.client));
    await SecureKeyStore.saveMnemonic(_phrase.split(' '));

    expect(core.held, _phrase);
    expect(await legacy.readAll(), isEmpty,
        reason: 'the plugin\'s storage is DPAPI on Windows: software');
    expect(await SecureKeyStore.loadMnemonic(), _phrase.split(' '));
    expect(await SecureKeyStore.protection(), 'hardware-wrapped');
  });

  test('where the core refuses, saving throws the root-seed refusal and nothing is kept', () async {
    final core = _FakeCore(refuse: true);
    SecureKeyStore.holdPhraseWith(CorePhraseHolder(baseUrl: _core, client: core.client));
    await expectLater(SecureKeyStore.saveMnemonic(_phrase.split(' ')),
        throwsA(isA<RootSeedRefused>()));
    expect(await legacy.readAll(), isEmpty);
  });

  test('a phrase the earlier version left in software is moved to the core, then deleted', () async {
    FlutterSecureStorage.setMockInitialValues({'agent_mnemonic': _phrase});
    final core = _FakeCore();
    SecureKeyStore.holdPhraseWith(CorePhraseHolder(baseUrl: _core, client: core.client));

    expect(await SecureKeyStore.loadMnemonic(), _phrase.split(' '));
    expect(core.held, _phrase);
    expect(await legacy.readAll(), isEmpty);
  });

  test('a phrase that cannot be moved stays where it is and is not served from there', () async {
    FlutterSecureStorage.setMockInitialValues({'agent_mnemonic': _phrase});
    final core = _FakeCore(refuse: true);
    SecureKeyStore.holdPhraseWith(CorePhraseHolder(baseUrl: _core, client: core.client));

    // the production rule: not run on the software copy
    await expectLater(SecureKeyStore.loadMnemonic(), throwsA(isA<RootSeedRefused>()));
    // but it is not destroyed either: the owner's only copy
    expect(await legacy.read(key: 'agent_mnemonic'), _phrase);
  });

  test('confirming the words are written down removes them from the core and says so only when they are gone', () async {
    final core = _FakeCore();
    SecureKeyStore.holdPhraseWith(CorePhraseHolder(baseUrl: _core, client: core.client));
    await SecureKeyStore.saveMnemonic(_phrase.split(' '));

    expect(await SecureKeyStore.forgetWordsAfterRecording(), isTrue);
    expect(core.held, isNull);
    expect(await SecureKeyStore.hasMnemonic(), isFalse);
  });

  test('an app closed before confirming finds the phrase still held, so recovery stays possible', () async {
    final core = _FakeCore();
    SecureKeyStore.holdPhraseWith(CorePhraseHolder(baseUrl: _core, client: core.client));
    await SecureKeyStore.saveMnemonic(_phrase.split(' '));

    // a new process: a fresh holder over the same core, nothing in memory
    SecureKeyStore.holdPhraseWith(CorePhraseHolder(baseUrl: _core, client: core.client));
    expect(await SecureKeyStore.loadMnemonic(), _phrase.split(' '));
  });

  test('a core that is not on this computer is never sent the phrase', () async {
    final core = _FakeCore();
    SecureKeyStore.holdPhraseWith(
        CorePhraseHolder(baseUrl: 'https://agent.example.com', client: core.client));
    await expectLater(SecureKeyStore.saveMnemonic(_phrase.split(' ')), throwsStateError);
    expect(core.seen, isEmpty);
  });
}
