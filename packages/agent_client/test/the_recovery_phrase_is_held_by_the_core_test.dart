import 'dart:convert';

import 'package:agent_client/services/profile_scope.dart';
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
  _FakeCore({this.refuse = false, this.refuseHoldOnly = false});
  final bool refuse;

  /// A production core that cannot wrap: it has nothing to open (404) and
  /// refuses only the hold, which is the only route that needs the wrapper.
  final bool refuseHoldOnly;
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
            if (refuseHoldOnly) {
              return http.Response(
                  jsonEncode({
                    'error': 'an identity cannot be created on this computer',
                    'details': 'its key protection is not proven usable',
                    'code': 'root_seed_refused'
                  }),
                  412);
            }
            final body = jsonDecode(req.body) as Map;
            final phrase = body['phrase'] as String;
            if (held != null && held != phrase && body['replace'] != true) {
              return _aDifferentPhraseIsHeld();
            }
            held = phrase;
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
  group("migration safety", migrationSafety);
  group("the phrase being moved to", phraseBeingMovedTo);
  late FlutterSecureStorage legacy;
  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
    ProfileScope.resetCacheForTest();
    legacy = const FlutterSecureStorage();
  });
  tearDown(SecureKeyStore.holdPhraseInTheCore);

  test(
      'saving the phrase puts it in the core and nowhere in the app\'s own storage',
      () async {
    final core = _FakeCore();
    SecureKeyStore.holdPhraseWith(
        CorePhraseHolder(baseUrl: _core, client: core.client));
    await SecureKeyStore.saveMnemonic(_phrase.split(' '));

    expect(core.held, _phrase);
    expect(await legacy.readAll(), isEmpty,
        reason: 'the plugin\'s storage is DPAPI on Windows: software');
    expect(await SecureKeyStore.loadMnemonic(), _phrase.split(' '));
    expect(await SecureKeyStore.protection(), 'hardware-wrapped');
  });

  test(
      'where the core refuses, saving throws the root-seed refusal and nothing is kept',
      () async {
    final core = _FakeCore(refuse: true);
    SecureKeyStore.holdPhraseWith(
        CorePhraseHolder(baseUrl: _core, client: core.client));
    await expectLater(SecureKeyStore.saveMnemonic(_phrase.split(' ')),
        throwsA(isA<RootSeedRefused>()));
    expect(await legacy.readAll(), isEmpty);
  });

  test(
      'a phrase the earlier version left in software is moved to the core, then deleted',
      () async {
    FlutterSecureStorage.setMockInitialValues({'agent_mnemonic': _phrase});
    final core = _FakeCore();
    SecureKeyStore.holdPhraseWith(
        CorePhraseHolder(baseUrl: _core, client: core.client));

    expect(await SecureKeyStore.loadMnemonic(), _phrase.split(' '));
    expect(core.held, _phrase);
    expect(await legacy.readAll(), isEmpty);
  });

  test(
      'a phrase that cannot be moved stays where it is and is not served from there',
      () async {
    FlutterSecureStorage.setMockInitialValues({'agent_mnemonic': _phrase});
    final core = _FakeCore(refuse: true);
    SecureKeyStore.holdPhraseWith(
        CorePhraseHolder(baseUrl: _core, client: core.client));

    // the production rule: not run on the software copy
    await expectLater(
        SecureKeyStore.loadMnemonic(), throwsA(isA<RootSeedRefused>()));
    // but it is not destroyed either: the owner's only copy
    expect(await legacy.read(key: 'agent_mnemonic'), _phrase);
  });

  test(
      'a core that answers 404 to open and refuses only the hold never lets the old copy be served',
      () async {
    FlutterSecureStorage.setMockInitialValues({'agent_mnemonic': _phrase});
    final core = _FakeCore(refuseHoldOnly: true);
    SecureKeyStore.holdPhraseWith(
        CorePhraseHolder(baseUrl: _core, client: core.client));

    await expectLater(
        SecureKeyStore.loadMnemonic(), throwsA(isA<RootSeedRefused>()));
    expect(await legacy.read(key: 'agent_mnemonic'), _phrase);
  });

  test(
      'confirming the words are written down removes them from the core and says so only when they are gone',
      () async {
    final core = _FakeCore();
    SecureKeyStore.holdPhraseWith(
        CorePhraseHolder(baseUrl: _core, client: core.client));
    await SecureKeyStore.saveMnemonic(_phrase.split(' '));

    expect(await SecureKeyStore.forgetWordsAfterRecording(), isTrue);
    expect(core.held, isNull);
    expect(await SecureKeyStore.hasMnemonic(), isFalse);
  });

  test('confirming deletes the old copies in the app\'s own storage too',
      () async {
    final scoped = await ProfileScope.key('mnemonic');
    FlutterSecureStorage.setMockInitialValues(
        {'agent_mnemonic': _phrase, scoped: _phrase});
    final core = _FakeCore()..held = _phrase;
    SecureKeyStore.holdPhraseWith(
        CorePhraseHolder(baseUrl: _core, client: core.client));

    expect(await SecureKeyStore.forgetWordsAfterRecording(), isTrue);
    expect(await legacy.readAll(), isEmpty,
        reason: 'a software copy left behind defeats the hardware hold');
    expect(core.held, isNull);
  });

  test('an old copy left by a crash after the hold is deleted on the next load',
      () async {
    FlutterSecureStorage.setMockInitialValues({'agent_mnemonic': _phrase});
    final core = _FakeCore()..held = _phrase;
    SecureKeyStore.holdPhraseWith(
        CorePhraseHolder(baseUrl: _core, client: core.client));

    expect(await SecureKeyStore.loadMnemonic(), _phrase.split(' '));
    expect(await legacy.readAll(), isEmpty);
  });

  test(
      'an old copy left by a crash after the hold is deleted at startup, before any load',
      () async {
    FlutterSecureStorage.setMockInitialValues({'agent_mnemonic': _phrase});
    final core = _FakeCore()..held = _phrase;
    SecureKeyStore.holdPhraseWith(
        CorePhraseHolder(baseUrl: _core, client: core.client));

    expect(await SecureKeyStore.hasMnemonic(), isTrue);
    expect(await legacy.readAll(), isEmpty);
  });

  test('moving the profile-scoped phrase leaves a different unscoped one alone',
      () async {
    final scoped = await ProfileScope.key('mnemonic');
    final other = _phrase.replaceFirst('about', 'above');
    FlutterSecureStorage.setMockInitialValues(
        {scoped: _phrase, 'agent_mnemonic': other});
    final core = _FakeCore();
    SecureKeyStore.holdPhraseWith(
        CorePhraseHolder(baseUrl: _core, client: core.client));

    expect(await SecureKeyStore.migrateLegacyMnemonic(), isFalse);
    expect(core.held, _phrase);
    expect(await legacy.read(key: scoped), isNull);
    expect(await legacy.read(key: 'agent_mnemonic'), other);
  });

  test(
      'an app closed before confirming finds the phrase still held, so recovery stays possible',
      () async {
    final core = _FakeCore();
    SecureKeyStore.holdPhraseWith(
        CorePhraseHolder(baseUrl: _core, client: core.client));
    await SecureKeyStore.saveMnemonic(_phrase.split(' '));

    // a new process: a fresh holder over the same core, nothing in memory
    SecureKeyStore.holdPhraseWith(
        CorePhraseHolder(baseUrl: _core, client: core.client));
    expect(await SecureKeyStore.loadMnemonic(), _phrase.split(' '));
  });

  test(
      'a second, different phrase is refused, and the phrase held is still the one held',
      () async {
    final core = _FakeCore();
    SecureKeyStore.holdPhraseWith(
        CorePhraseHolder(baseUrl: _core, client: core.client));
    await SecureKeyStore.saveMnemonic(_phrase.split(' '));

    await expectLater(SecureKeyStore.saveMnemonic(_movingTo.split(' ')),
        throwsA(isA<ADifferentPhraseIsHeld>()));
    expect(core.held, _phrase);
    // the same phrase again is not a change
    await SecureKeyStore.saveMnemonic(_phrase.split(' '));
    expect(core.held, _phrase);
  });

  test('a core that does not answer is "unknown" at startup, never "no phrase"',
      () async {
    SecureKeyStore.holdPhraseWith(CorePhraseHolder(
        baseUrl: _core,
        client: MockClient(
            (_) async => throw http.ClientException('connection refused'))));
    await expectLater(SecureKeyStore.hasMnemonic(),
        throwsA(isA<WhetherAPhraseIsHeldIsUnknown>()));
  });

  test('a core that is not on this computer is never sent the phrase',
      () async {
    final core = _FakeCore();
    SecureKeyStore.holdPhraseWith(CorePhraseHolder(
        baseUrl: 'https://agent.example.com', client: core.client));
    await expectLater(
        SecureKeyStore.saveMnemonic(_phrase.split(' ')), throwsStateError);
    expect(core.seen, isEmpty);
  });
}

void migrationSafety() {
  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
    ProfileScope.resetCacheForTest();
  });
  tearDown(SecureKeyStore.holdPhraseInTheCore);

  test('an old phrase that differs from the one the core holds is not deleted',
      () async {
    FlutterSecureStorage.setMockInitialValues({'agent_mnemonic': _phrase});
    final core = _FakeCore()..held = _phrase.replaceFirst('about', 'above');
    SecureKeyStore.holdPhraseWith(
        CorePhraseHolder(baseUrl: _core, client: core.client));
    expect(await SecureKeyStore.migrateLegacyMnemonic(), isFalse);
    expect(await const FlutterSecureStorage().read(key: 'agent_mnemonic'),
        _phrase);
  });

  test('an old phrase with stray whitespace is moved in its normal form',
      () async {
    FlutterSecureStorage.setMockInitialValues(
        {'agent_mnemonic': '$_phrase \n'});
    final core = _FakeCore();
    SecureKeyStore.holdPhraseWith(
        CorePhraseHolder(baseUrl: _core, client: core.client));
    expect(await SecureKeyStore.migrateLegacyMnemonic(), isTrue);
    expect(core.held, _phrase);
  });
}

const _movingTo = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';

/// The core's answer to a different phrase held, as the core gives it.
http.Response _aDifferentPhraseIsHeld() => http.Response(
    jsonEncode({
      'error': 'a different phrase is already held on this agent',
      'code': 'a_different_phrase_is_held'
    }),
    409);

/// A core with both slots: the phrase in force, and the phrase moved to.
class _TwoSlotCore {
  String? inForce;
  String? movingTo;

  /// Runs once, when the first PUT arrives and before it is answered: what
  /// another app process did between this one's open and its hold.
  Future<void> Function()? beforeFirstPut;

  MockClient get client => MockClient((req) async {
        final moving = req.url.path.contains('/moving-to');
        String? get() => moving ? movingTo : inForce;
        void set(String? v) => moving ? movingTo = v : inForce = v;
        switch (req.method) {
          case 'PUT':
            final meanwhile = beforeFirstPut;
            beforeFirstPut = null;
            if (meanwhile != null) await meanwhile();
            final body = jsonDecode(req.body) as Map;
            final phrase = body['phrase'] as String;
            if (get() != null && get() != phrase && body['replace'] != true) {
              return _aDifferentPhraseIsHeld();
            }
            set(phrase);
            return http.Response('{"held":true}', 201);
          case 'POST':
            return get() == null
                ? http.Response('{"error":"none"}', 404)
                : http.Response(jsonEncode({'phrase': get()}), 200);
          case 'GET':
            return http.Response(jsonEncode({'held': get() != null}), 200);
          case 'DELETE':
            set(null);
            return http.Response('{"held":false}', 200);
        }
        return http.Response('', 404);
      });
}

void phraseBeingMovedTo() {
  late _TwoSlotCore core;
  late FlutterSecureStorage storage;
  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
    storage = const FlutterSecureStorage();
    core = _TwoSlotCore();
    SecureKeyStore.holdPhraseWith(
        CorePhraseHolder(baseUrl: _core, client: core.client),
        movingTo:
            CorePhraseHolder.movingTo(baseUrl: _core, client: core.client));
  });
  tearDown(SecureKeyStore.holdPhraseInTheCore);

  // Losing either phrase between a move's two rotations loses the identity, so
  // the one moved to is held where the other is, and never in the app's storage.
  test(
      'the phrase moved to is held by the core under its own route, never in the app\'s own storage',
      () async {
    await SecureKeyStore.saveMnemonic(_phrase.split(' '));
    expect(
        await SecureKeyStore.savePhraseMovingTo(_movingTo.split(' ')), isTrue);
    expect(core.movingTo, _movingTo);
    expect(core.inForce, _phrase, reason: 'the phrase in force is untouched');
    expect(await SecureKeyStore.loadPhraseMovingTo(), _movingTo.split(' '));

    final everything = await storage.readAll();
    expect(everything.values.where((v) => v.contains('zoo')), isEmpty,
        reason: 'the phrase moved to landed in flutter_secure_storage');
    expect(everything.keys.where((k) => k.contains('moving')), isEmpty);
  });

  test(
      'finishing the move makes it the phrase in force in the core and forgets the record of the move',
      () async {
    await SecureKeyStore.saveMnemonic(_phrase.split(' '));
    await SecureKeyStore.savePhraseMovingTo(_movingTo.split(' '));
    expect(await SecureKeyStore.finishMovingToThePhrase(_movingTo.split(' ')),
        isTrue);
    expect(core.inForce, _movingTo);
    expect(core.movingTo, isNull);
    expect(await SecureKeyStore.loadPhraseMovingTo(), isNull);
    expect((await storage.readAll()).values.where((v) => v.contains('zoo')),
        isEmpty);
  });

  // Two app processes: this one moves an old software copy of the phrase to
  // the core, reads "none held", and before its hold arrives the other
  // finishes a phrase move. The phrase now in force must survive.
  test(
      'a migration racing a finished move leaves the phrase the move made in force',
      () async {
    await storage.write(key: 'agent_mnemonic', value: _phrase);
    core.movingTo = _movingTo;
    core.beforeFirstPut =
        () => SecureKeyStore.finishMovingToThePhrase(_movingTo.split(' '));

    expect(await SecureKeyStore.migrateLegacyMnemonic(), isFalse);
    expect(core.inForce, _movingTo,
        reason: 'the migration overwrote the phrase in force');
    expect(core.movingTo, isNull);
  });

  test('clearing a move that cannot happen keeps the phrase in force',
      () async {
    await SecureKeyStore.saveMnemonic(_phrase.split(' '));
    await SecureKeyStore.savePhraseMovingTo(_movingTo.split(' '));
    await SecureKeyStore.clearPhraseMovingTo();
    expect(core.movingTo, isNull);
    expect(core.inForce, _phrase);
  });

  test(
      'a phrase moved to that #347 left in software is moved to the core, compared, then deleted',
      () async {
    final key = await ProfileScope.key('mnemonic_moving_to');
    await storage.write(key: key, value: _movingTo);
    expect(await SecureKeyStore.loadPhraseMovingTo(), _movingTo.split(' '));
    expect(core.movingTo, _movingTo);
    expect(await storage.read(key: key), isNull);
  });

  test(
      'a software copy is kept when the core holds a different phrase moved to',
      () async {
    final key = await ProfileScope.key('mnemonic_moving_to');
    await storage.write(key: key, value: _movingTo);
    core.movingTo = _movingTo.replaceFirst('wrong', 'wrote');
    await SecureKeyStore.loadPhraseMovingTo();
    expect(await storage.read(key: key), _movingTo);
  });

  test('a startup question about the phrase finishes an interrupted move of it',
      () async {
    final key = await ProfileScope.key('mnemonic_moving_to');
    await storage.write(key: key, value: _movingTo);
    await SecureKeyStore.hasMnemonic();
    expect(core.movingTo, _movingTo);
    expect(await storage.read(key: key), isNull);
  });

  test('where the core refuses, the phrase moved to is not kept anywhere',
      () async {
    SecureKeyStore.holdPhraseWith(
        CorePhraseHolder(
            baseUrl: _core, client: _FakeCore(refuse: true).client),
        movingTo: CorePhraseHolder.movingTo(
            baseUrl: _core, client: _FakeCore(refuse: true).client));
    await expectLater(SecureKeyStore.savePhraseMovingTo(_movingTo.split(' ')),
        throwsA(isA<RootSeedRefused>()));
    expect((await storage.readAll()).values.where((v) => v.contains('zoo')),
        isEmpty);
  });
}
