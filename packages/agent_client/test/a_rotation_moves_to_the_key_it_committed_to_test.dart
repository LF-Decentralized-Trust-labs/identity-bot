import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/crypto/owner_signature.dart';
import 'package:agent_client/services/local_core_keri_service.dart';
import 'package:agent_client/services/keri_service.dart';
import 'package:agent_client/services/owner_signing_client.dart';
import 'package:agent_client/services/secure_key_store.dart';
import 'package:agent_client/services/the_events_this_device_asked_for.dart';
import 'package:agent_client/services/the_key_in_force.dart';
import 'package:agent_client/services/the_key_is_not_held_by_the_core.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

// The raw 32 bytes behind a qb64 key with a one-character code.
List<int> rawOf(String qb64) => base64Url.decode('A${qb64.substring(1)}').sublist(1);

// A core that keeps a key log the way the real one does: founding puts the key
// it is handed in force, a rotation puts the new key in force, an interaction
// changes no key. It outlives any one LocalCoreKeriService, as the real core
// outlives the app talking to it.
//
// Like the real core it records a signature over an event only if it verifies
// under the key that event is checked against, records the same one again
// without complaint, and says in its key log which events are signed.
//
// [keyNotHeldHere] is the real core's answer today for an identity whose key
// the app holds: it refuses to add a rotation or an interaction at all
// (409 key_not_held_here), because it cannot sign one itself. What this test
// shows about rotations and interactions is the app's half, ready for a core
// that accepts an event the app signs.
class FakeCore {
  final kel = <Map<String, dynamic>>[];
  // The bytes each event was published as, beside it.
  final raws = <List<int>>[];
  final sent = <String, Map<String, dynamic>>{};
  final posted = <String>[];
  bool refuseSignatures = false;
  bool keyNotHeldHere = false;
  // Rewrites the bytes served for an unsigned event, as a core lying about
  // what an event is would.
  Map<String, dynamic> Function(Map<String, dynamic>)? tamper;
  // Makes the founding or rotation the core builds commit to somebody else's
  // next key.
  String? foreignNext;
  // What the core anchors when it issues a credential, if not the credential.
  List<Object?>? credentialAnchor;
  // Rewrites the rotation the core builds, or the anchors of an interaction.
  Map<String, dynamic> Function(Map<String, dynamic>)? changeRotation;
  List<Object?>? interactionAnchors;
  // A path whose request fails in transit, before or after the core acts on it.
  String? dropsRequestsTo;
  String? dropsAnswersFrom;
  // Numbers the next event one past where it belongs.
  bool skipsASequenceNumber = false;
  // Writes another identifier into the credential anchor it builds.
  String? anchorsAs;
  // Adds to a founding what the real core adds of its own: a post-quantum
  // next-key commitment and an anchor of the identity's messaging keys.
  bool addsItsOwn = false;
  // Rewrites the founding the core builds.
  Map<String, dynamic> Function(Map<String, dynamic>)? changeFounding;

  static const keysetAnchor = {'ia': 'IA-HYBRID-1', 'ka': ['Ckem'], 'sa': ['Dsig']};
  // Answers 404 to a signature, as a core that does not hold the event does.
  bool forgetsEvents = false;

  // The key an event at [sn] is checked against: the one in force at it.
  String keyFor(int sn) =>
      (kel.sublist(0, sn + 1).lastWhere((e) => e['t'] != 'ixn')['k'] as List).first as String;

  String? get currentKey =>
      (kel.lastWhere((e) => e['t'] != 'ixn')['k'] as List).first as String;

  List<int> raw(int sn) => raws[sn];

  static String commitmentTo(String key) => OwnerSignature.blake3QB64(utf8.encode(key));

  // Appends an event, laid out as the engine lays one out.
  void add(Map<String, dynamic> event) {
    final sn = (kel.length + (skipsASequenceNumber ? 1 : 0)).toRadixString(16);
    // A founding's digest is the identifier it founds.
    final e = <String, dynamic>{
      'v': 'KERI10JSON', 't': event['t'], 'd': event['d'] ?? (event['t'] == 'icp' ? 'Eaid' : 'Eevent$sn'), 'i': 'Eaid', 's': sn,
    };
    for (final f in ['kt', 'k', 'nt', 'n', 'bt', 'b', 'br', 'ba', 'c', 'a']) {
      if (event.containsKey(f)) e[f] = event[f];
    }
    raws.add(utf8.encode(jsonEncode(e)));
    kel.add({...e, if (event['sig'] != null) 'sig': event['sig']});
  }

  // A rotation to [key], committing to [next], as the engine writes one.
  static Map<String, dynamic> rotation(String key, String next) =>
      {'t': 'rot', 'kt': '1', 'k': [key], 'nt': '1', 'n': [commitmentTo(next)], 'bt': '0', 'br': [], 'ba': [], 'a': []};

  http.Client client() => MockClient((req) async {
        if (req.method == 'GET') {
          switch (req.url.path) {
            case '/api/identity':
              return http.Response(jsonEncode(kel.isEmpty ? {'initialized': false} : {'initialized': true, 'aid': 'Eaid'}), 200);
            case '/api/kel':
              if (req.url.queryParameters['name'] != 'Eaid') {
                return http.Response(jsonEncode({'error': 'no identity named that'}), 500);
              }
              return http.Response(
                  jsonEncode({
                    'aid': 'Eaid',
                    'kel': kel,
                    'raw_events_b64': [
                      for (var i = 0; i < kel.length; i++)
                        base64Encode(tamper != null && kel[i]['sig'] == null
                            ? utf8.encode(jsonEncode(tamper!(Map<String, dynamic>.from(jsonDecode(utf8.decode(raws[i])) as Map))))
                            : raws[i]),
                    ],
                    'sequence_number': kel.length - 1,
                    'event_count': kel.length,
                    'signed': [for (final e in kel) e['sig'] != null],
                  }),
                  200);
          }
          return http.Response('{}', 404);
        }
        final body = jsonDecode(req.body) as Map<String, dynamic>;
        sent[req.url.path] = body;
        posted.add(req.url.path);
        if (req.url.path == dropsRequestsTo) throw http.ClientException('the connection dropped');
        if (keyNotHeldHere && (req.url.path == '/api/rotation' || req.url.path == '/api/interact')) {
          return http.Response(
              jsonEncode({'error': 'key_not_held_here', 'details': "This identity's key is not held by this Identity Agent."}),
              409);
        }
        switch (req.url.path) {
          case '/api/inception':
            final founding = <String, dynamic>{
              't': 'icp', 'kt': '1', 'k': [body['public_key']], 'nt': '1',
              'n': [
                foreignNext != null ? commitmentTo(foreignNext!) : commitmentTo(body['next_public_key'] as String),
                if (addsItsOwn) 'Epostquantumdigest',
              ],
              'bt': '0', 'b': [], 'c': [], 'a': [if (addsItsOwn) keysetAnchor],
            };
            add(changeFounding != null ? changeFounding!(founding) : founding);
          case '/api/rotation':
            final r = rotation(body['new_public_key'] as String, foreignNext ?? body['new_next_public_key'] as String);
            add(changeRotation != null ? changeRotation!(r) : r);
          case '/api/interact':
            add({'t': 'ixn', 'a': interactionAnchors ?? body['data']});
          case '/api/credential/issue':
            add({'t': 'ixn', 'a': credentialAnchor ?? [{'i': 'Ecredential', 's': '0', 'd': 'Ecredential'}]});
            if (anchorsAs != null) {
              final e = Map<String, dynamic>.from(jsonDecode(utf8.decode(raws.last)) as Map)..['i'] = anchorsAs;
              raws[raws.length - 1] = utf8.encode(jsonEncode(e));
              kel[kel.length - 1]['i'] = anchorsAs;
            }
          case '/api/cesr/encode':
            // Carries the raw signature through, so the core can check it.
            return http.Response(jsonEncode({'cesr_sig': body['raw_sig_b64']}), 200);
          case '/api/events/signature':
            if (forgetsEvents) return http.Response(jsonEncode({'error': 'No such event'}), 404);
            final at = body['sequence_number'] as int;
            final sig = base64Decode(body['cesr_signature'] as String);
            if (refuseSignatures || at >= kel.length ||
                !ed.verify(ed.PublicKey(rawOf(keyFor(at))), Uint8List.fromList(raws[at]), sig)) {
              return http.Response(jsonEncode({'error': 'That signature does not cover this event'}), 400);
            }
            kel[at]['sig'] = body['cesr_signature'];
            return http.Response(jsonEncode({'status': 'signed'}), 200);
          default:
            return http.Response('{}', 200);
        }
        if (req.url.path == dropsAnswersFrom) throw http.ClientException('the answer was lost');
        final raw = base64Encode(raws.last);
        return http.Response(
            jsonEncode({
              'aid': 'Eaid',
              'raw_bytes_b64': raw,
              'ixn_raw_bytes_b64': raw,
              'acdc_said': 'Ecredential',
              'sequence_number': kel.length - 1,
            }),
            200);
      });
}

void main() {
  final words = Bip39.generateMnemonic();

  late FakeCore core;
  late Map<String, Map<String, dynamic>> sent;
  late LocalCoreKeriService keri;

  // The signature most recently handed to the core to CESR-encode.
  Uint8List lastSignature() =>
      base64Decode(sent['/api/cesr/encode']!['raw_sig_b64'] as String);

  bool verifiesUnder(String qb64, List<int> data, List<int> sig) => ed.verify(
      ed.PublicKey(rawOf(qb64)), Uint8List.fromList(data), Uint8List.fromList(sig));

  setUp(() async {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
    await SecureKeyStore.saveMnemonic(words);
    core = FakeCore();
    sent = core.sent;
    keri = LocalCoreKeriService(baseUrl: 'http://core.test', client: core.client());
  });

  test('a rotation names the key founding committed to, and that key signs it', () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    final committed = sent['/api/inception']!['next_public_key'] as String;

    await keri.rotateAid(name: 'Eaid');
    final rotation = sent['/api/rotation']!;
    expect(rotation['new_public_key'], committed,
        reason: 'the new key must be the next key the founding event committed to');

    // The signature handed back for the rotation verifies under the key it names.
    final sig = base64Decode(sent['/api/cesr/encode']!['raw_sig_b64'] as String);
    final named = ed.PublicKey(rawOf(rotation['new_public_key'] as String));
    expect(ed.verify(named, Uint8List.fromList(core.raw(1)), Uint8List.fromList(sig)), isTrue,
        reason: 'the key the rotation names must be the key that signs it');

    // And the rotation commits to the key after it, derived the same way.
    final seed = Bip39.mnemonicToSeed(words);
    expect(rotation['new_next_public_key'], KeyManager.keyAt(seed, 2).publicKeyEncoded);
    expect(rotation['new_next_public_key'], isNot(rotation['new_public_key']));
  });

  test('every key in the chain comes from signingSeed', () {
    final seed = Bip39.mnemonicToSeed(words);
    final keys = KeyManager.generateKeysFromMnemonic(words);
    for (final (index, pair) in [(0, keys.signing), (1, keys.next)]) {
      final fromSeed = ed.public(ed.newKeyFromSeed(KeyManager.signingSeed(seed, index: index)));
      expect(pair.publicKey, fromSeed.bytes);
      expect(KeyManager.keyAt(seed, index).publicKey, fromSeed.bytes);
    }
    expect(KeyManager.signingSeed(seed), KeyManager.signingSeed(seed, index: 0));
    expect(() => KeyManager.signingSeed(seed, index: -1), throwsArgumentError);
    expect(() => KeyManager.signingSeed(seed, index: 0x80000000), throwsArgumentError);
  });

  test('a signature made as the identity reports the key that made it', () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    final data = utf8.encode('hello');
    final result = await keri.signPayload(name: 'me', data: data);
    final key = ed.PublicKey(rawOf(result.publicKey));
    expect(ed.verify(key, Uint8List.fromList(data), base64Decode(result.signature)), isTrue);
  });

  test('after a rotation, an interaction and a signature are made by the rotated key',
      () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    await keri.rotateAid(name: 'Eaid');
    final inForce = core.currentKey!;
    expect(inForce, KeyManager.keyAt(Bip39.mnemonicToSeed(words), 1).publicKeyEncoded);

    await keri.interactAid(name: 'Eaid');
    expect(verifiesUnder(inForce, core.raw(2), lastSignature()), isTrue,
        reason: 'an interaction after a rotation is signed by the key the log says is in force');

    final data = utf8.encode('after the rotation');
    final result = await keri.signPayload(name: 'Eaid', data: data);
    expect(result.publicKey, inForce,
        reason: 'the key reported is the key in force, not the founding key');
    expect(verifiesUnder(inForce, data, base64Decode(result.signature)), isTrue);

    await keri.issueCredential(claims: {'role': 'engineer'}, schemaSaid: 'Eschema');
    expect(verifiesUnder(inForce, core.raw(3), lastSignature()), isTrue,
        reason: 'the event anchoring a credential is signed by the key in force');
  });

  test('a second rotation reveals the key the first committed to, and commits to the next',
      () async {
    final seed = Bip39.mnemonicToSeed(words);
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    await keri.rotateAid(name: 'Eaid');
    final first = Map<String, dynamic>.from(sent['/api/rotation']!);

    await keri.rotateAid(name: 'Eaid');
    final second = sent['/api/rotation']!;
    expect(second['new_public_key'], first['new_next_public_key'],
        reason: 'the second rotation reveals the key the first committed to');
    expect(second['new_public_key'], KeyManager.keyAt(seed, 2).publicKeyEncoded);
    expect(second['new_next_public_key'], KeyManager.keyAt(seed, 3).publicKeyEncoded);
    expect(verifiesUnder(second['new_public_key'] as String, core.raw(2), lastSignature()), isTrue,
        reason: 'the key the second rotation names is the key that signs it');
  });

  test('the key in force is still known after the app restarts', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    await keri.rotateAid(name: 'Eaid');

    // A new service against the same core: nothing carried over in memory.
    final restarted = LocalCoreKeriService(baseUrl: 'http://core.test', client: core.client());
    final data = utf8.encode('after a restart');
    final result = await restarted.signPayload(name: 'Eaid', data: data);
    expect(result.publicKey, core.currentKey);
    expect(verifiesUnder(core.currentKey!, data, base64Decode(result.signature)), isTrue);

    await restarted.rotateAid(name: 'Eaid');
    expect(sent['/api/rotation']!['new_public_key'],
        KeyManager.keyAt(Bip39.mnemonicToSeed(words), 2).publicKeyEncoded);
  });

  test('nothing is signed when the log names a key this phrase does not hold', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    final stranger = Bip39.mnemonicToSeed(Bip39.generateMnemonic());
    core.add(FakeCore.rotation(KeyManager.keyAt(stranger, 1).publicKeyEncoded, KeyManager.keyAt(stranger, 2).publicKeyEncoded));
    await expectLater(keri.signPayload(name: 'Eaid', data: [1, 2, 3]), throwsException);
  });

  test('a rotation and an interaction end up signed in the key log', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    await keri.rotateAid(name: 'Eaid');
    await keri.interactAid(name: 'Eaid');
    await keri.rotateAid(name: 'Eaid');
    expect(core.kel.map((e) => e['t']), ['icp', 'rot', 'ixn', 'rot']);
    for (final (sn, event) in core.kel.indexed) {
      expect(event['sig'], isNotNull, reason: 'event $sn (${event['t']}) was left unsigned in the log');
      expect(
          verifiesUnder(core.keyFor(sn), core.raw(sn), base64Decode(event['sig'] as String)), isTrue,
          reason: 'event $sn is signed by the key it is checked against');
    }
  });

  test('a rotation whose signature the core refuses says so', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    core.refuseSignatures = true;
    await expectLater(keri.rotateAid(name: 'Eaid'), throwsA(predicate((e) => '$e'.contains('was refused'))));
    await expectLater(keri.interactAid(name: 'Eaid'), throwsException);
  });

  test('the key log is read as the list of events the core sends', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    await keri.rotateAid(name: 'Eaid');
    final log = await keri.getCurrentKel(name: 'Eaid');
    expect(log.aid, 'Eaid');
    expect(log.events.map((e) => e['t']), ['icp', 'rot']);
    expect(log.rawEventsB64, [base64Encode(core.raw(0)), base64Encode(core.raw(1))]);
    expect(log.sequenceNumber, 1);
    expect(log.eventCount, 2);
    expect(log.establishmentEvents.last['k'], [core.currentKey]);
  });

  test('where the core does not hold the key, a rotation says so and signs nothing', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    core.keyNotHeldHere = true;
    core.posted.clear();
    await expectLater(keri.rotateAid(name: 'Eaid'), throwsA(isA<KeyNotHeldByTheCore>()));
    await expectLater(keri.interactAid(name: 'Eaid'), throwsA(isA<KeyNotHeldByTheCore>()));
    expect(core.posted.where((p) => p == '/api/cesr/encode' || p == '/api/events/signature'), isEmpty,
        reason: 'nothing is signed for an event the core refused to add');
    expect(core.kel.map((e) => e['t']), ['icp']);
  });

  test('only the identity held here is rotated with its phrase', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    core.posted.clear();
    await expectLater(keri.rotateAid(name: 'Esomebody-else'), throwsArgumentError);
    expect(core.posted, isNot(contains('/api/rotation')));
  });

  test('the key is worked out before the event exists', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    // A log naming a key this phrase does not hold.
    final stranger = KeyManager.keyAt(Bip39.mnemonicToSeed(Bip39.generateMnemonic()), 1);
    core.add({...FakeCore.rotation(stranger.publicKeyEncoded, stranger.publicKeyEncoded), 'sig': 'x'});
    core.posted.clear();
    await expectLater(keri.interactAid(name: 'Eaid'), throwsException);
    await expectLater(keri.issueCredential(claims: {'a': 'b'}, schemaSaid: 'E'), throwsException);
    expect(core.posted, isEmpty, reason: 'no event is added to a log this phrase cannot sign for');
  });

  test('an establishment event left unsigned is signed the next time the identity signs', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    core.refuseSignatures = true;
    await expectLater(keri.rotateAid(name: 'Eaid'), throwsException);
    expect(core.kel.last['t'], 'rot');
    expect(core.kel.last['sig'], isNull, reason: 'the rotation is stranded: added and never signed');

    core.refuseSignatures = false;
    final data = utf8.encode('after the connection came back');
    final result = await keri.signPayload(name: 'Eaid', data: data);
    expect(core.kel.last['sig'], isNotNull, reason: 'the stranded rotation was finished');
    expect(verifiesUnder(core.keyFor(1), core.raw(1), base64Decode(core.kel.last['sig'] as String)), isTrue);
    expect(result.publicKey, core.currentKey);

    // And the next rotation builds on it.
    await keri.rotateAid(name: 'Eaid');
    expect(sent['/api/rotation']!['new_public_key'],
        KeyManager.keyAt(Bip39.mnemonicToSeed(words), 2).publicKeyEncoded);
  });

  test('a request signed as the owner is signed with the key in force', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    await keri.rotateAid(name: 'Eaid');
    final reader = seedFromMnemonic(
      () async => words,
      (m) => Bip39.mnemonicToSeed(m.split(' ')),
      TheKeyInForce(core.client(), 'http://core.test').index,
    );
    final ownerSeed = await reader();
    expect(KeyManager.keyAt(Bip39.mnemonicToSeed(words), 1).publicKey,
        ed.public(ed.newKeyFromSeed(ownerSeed!)).bytes,
        reason: 'after a rotation the owner is the rotated key, not the founding one');
  });

  test('an answer that is not a key log is refused, not read as an empty one', () {
    expect(() => KeyEventLog.fromJson({'kel': []}), throwsFormatException);
    expect(() => KeyEventLog.fromJson({'aid': 'Eaid'}), throwsFormatException);
    expect(() => KeyEventLog.fromJson({'aid': 'Eaid', 'kel': 'x'}), throwsFormatException);
    expect(KeyEventLog.fromJson({'aid': 'Eaid', 'kel': []}).events, isEmpty);
  });

  test('an interaction left unsigned is signed with the key in force at it', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    await keri.rotateAid(name: 'Eaid');
    core.refuseSignatures = true;
    await expectLater(keri.interactAid(name: 'Eaid'), throwsException);
    expect(core.kel.last['t'], 'ixn');
    expect(core.kel.last['sig'], isNull, reason: 'the interaction is stranded');

    core.refuseSignatures = false;
    await keri.signPayload(name: 'Eaid', data: [1, 2, 3]);
    final ixn = core.kel.length - 1;
    expect(core.kel[ixn]['sig'], isNotNull, reason: 'the stranded interaction was finished');
    expect(verifiesUnder(KeyManager.keyAt(Bip39.mnemonicToSeed(words), 1).publicKeyEncoded, core.raw(ixn),
        base64Decode(core.kel[ixn]['sig'] as String)), isTrue,
        reason: 'signed by the key in force at it: the rotated key, not the founding one');
  });

  test('bytes that differ from the event in one field are not signed', () async {
    final cases = <String, Map<String, dynamic> Function(Map<String, dynamic>)>{
      'its digest': (e) => {...e, 'd': 'Eanother'},
      'its keys': (e) => {...e, 'k': [KeyManager.keyAt(Bip39.mnemonicToSeed(Bip39.generateMnemonic()), 1).publicKeyEncoded]},
      'its sequence number': (e) => {...e, 's': 'f'},
      'its identifier': (e) => {...e, 'i': 'Eother'},
    };
    for (final MapEntry(key: what, value: change) in cases.entries) {
      FlutterSecureStorage.setMockInitialValues({});
      SharedPreferences.setMockInitialValues({});
      await SecureKeyStore.saveMnemonic(words);
      core = FakeCore();
      keri = LocalCoreKeriService(baseUrl: 'http://core.test', client: core.client());
      await keri.inceptAid(name: 'Eaid', code: words.join(' '));
      core.refuseSignatures = true;
      await expectLater(keri.rotateAid(name: 'Eaid'), throwsException);
      core.refuseSignatures = false;
      core.tamper = change;
      core.posted.clear();
      await expectLater(keri.signPayload(name: 'Eaid', data: [1]), throwsException, reason: what);
      expect(core.posted, isNot(contains('/api/cesr/encode')),
          reason: 'bytes that differ from the event in $what are never signed');
    }
  });

  test('a stranded event the core will not take a signature for stops signing, and says why', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    core.refuseSignatures = true;
    await expectLater(keri.interactAid(name: 'Eaid'), throwsException);
    core.refuseSignatures = false;
    core.forgetsEvents = true;
    await expectLater(keri.signPayload(name: 'Eaid', data: [1]), throwsA(isA<StrandedEventCannotBeFinished>()));
  });

  test('the key in force is read through a plain client, never the owner-signing one', () {
    final signing = OwnerSigningClient(agentOrigin: 'http://core.test', ownerSeed: () async => null);
    expect(() => TheKeyInForce(signing, 'http://core.test'), throwsArgumentError);
    signing.close();
  });

  test('a credential is not asked for where there is no phrase to sign it with', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    await SecureKeyStore.clearMnemonic();
    core.posted.clear();
    await expectLater(keri.issueCredential(claims: {'a': 'b'}, schemaSaid: 'E'),
        throwsA(predicate((e) => '$e'.contains('No identity keys found in secure storage.'))));
    await expectLater(keri.presentCredential(acdcSaid: 'Ex', holderAid: 'Eaid'),
        throwsA(predicate((e) => '$e'.contains('No identity keys found in secure storage.'))));
    expect(core.posted, isEmpty, reason: 'nothing is asked of the core that could not then be signed');
  });

  test('a rotation the core added on its own, committing to its own key, is never signed', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    final seed = Bip39.mnemonicToSeed(words);
    final attacker = KeyManager.keyAt(Bip39.mnemonicToSeed(Bip39.generateMnemonic()), 0).publicKeyEncoded;
    // Reveals this phrase's key 1, as a real rotation would, and commits to
    // the attacker's key, marked unsigned so the device would finish it.
    core.add(FakeCore.rotation(KeyManager.keyAt(seed, 1).publicKeyEncoded, attacker));
    core.posted.clear();
    await expectLater(keri.signPayload(name: 'Eaid', data: [1]), throwsA(isA<AnEventThisDeviceDidNotAskFor>()));
    expect(core.posted, isNot(contains('/api/cesr/encode')));
  });

  test('an interaction the core added on its own is never signed', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    core.add({'t': 'ixn', 'a': [{'d': 'Esomething the core wants anchored'}]});
    core.posted.clear();
    await expectLater(keri.signPayload(name: 'Eaid', data: [1]), throwsA(isA<AnEventThisDeviceDidNotAskFor>()));
    expect(core.posted, isNot(contains('/api/cesr/encode')));
  });

  test('a rotation that commits to any key but the next one is not signed', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    core.foreignNext = KeyManager.keyAt(Bip39.mnemonicToSeed(Bip39.generateMnemonic()), 0).publicKeyEncoded;
    core.posted.clear();
    await expectLater(keri.rotateAid(name: 'Eaid'), throwsA(predicate((e) => '$e'.contains('not to the next key'))));
    expect(core.posted, isNot(contains('/api/cesr/encode')));
    // Nor is it signed later, though this device did ask for a rotation.
    await expectLater(keri.signPayload(name: 'Eaid', data: [1]), throwsException);
    expect(core.posted, isNot(contains('/api/cesr/encode')));
  });

  test('an interaction left unsigned before a rotation is signed with the key in force at it', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    core.refuseSignatures = true;
    await expectLater(keri.interactAid(name: 'Eaid'), throwsException);
    core.refuseSignatures = false;
    final ixn = core.kel.length - 1;
    // A rotation added and signed since, by this device on another occasion.
    final seed = Bip39.mnemonicToSeed(words);
    core.add({...FakeCore.rotation(KeyManager.keyAt(seed, 1).publicKeyEncoded, KeyManager.keyAt(seed, 2).publicKeyEncoded), 'sig': 'x'});
    await keri.signPayload(name: 'Eaid', data: [1]);
    expect(core.kel[ixn]['sig'], isNotNull);
    expect(verifiesUnder(KeyManager.keyAt(seed, 0).publicKeyEncoded, core.raw(ixn),
        base64Decode(core.kel[ixn]['sig'] as String)), isTrue,
        reason: 'the interaction came before the rotation, so the founding key signs it, not the key in force now');
  });

  Future<List<Map<String, dynamic>>> pending() async {
    final asked = TheEventsThisDeviceAskedFor();
    return asked.pending(await asked.scope());
  }

  test('a founding that commits to somebody else\'s next key is never signed', () async {
    core.foreignNext = KeyManager.keyAt(Bip39.mnemonicToSeed(Bip39.generateMnemonic()), 0).publicKeyEncoded;
    await expectLater(keri.inceptAid(name: 'Eaid', code: words.join(' ')),
        throwsA(predicate((e) => '$e'.contains('not the one this device asked for'))));
    expect(core.posted, isNot(contains('/api/cesr/encode')));
    expect(await pending(), isEmpty, reason: 'a founding refused here is nothing to finish later');
  });

  test('a rotation that changes anything this device did not ask for is not signed', () async {
    final cases = <String, Map<String, dynamic> Function(Map<String, dynamic>)>{
      'a witness removed': (r) => {...r, 'br': ['Ewitness']},
      'a witness added': (r) => {...r, 'ba': ['Ewitness']},
      'the witness threshold': (r) => {...r, 'bt': '1'},
      'the signing threshold': (r) => {...r, 'kt': '2'},
      'the next threshold': (r) => {...r, 'nt': '2'},
      'an anchor': (r) => {...r, 'a': [{'d': 'Esomething'}]},
    };
    for (final MapEntry(key: what, value: change) in cases.entries) {
      FlutterSecureStorage.setMockInitialValues({});
      SharedPreferences.setMockInitialValues({});
      await SecureKeyStore.saveMnemonic(words);
      core = FakeCore();
      keri = LocalCoreKeriService(baseUrl: 'http://core.test', client: core.client());
      await keri.inceptAid(name: 'Eaid', code: words.join(' '));
      core.changeRotation = change;
      core.posted.clear();
      await expectLater(keri.rotateAid(name: 'Eaid'), throwsException, reason: what);
      expect(core.posted, isNot(contains('/api/cesr/encode')), reason: 'a rotation with $what changed was signed');
      expect(await pending(), isEmpty, reason: 'a rotation refused here is nothing to finish later');
    }
  });

  test('an interaction anchoring anything but what was asked is not signed', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    core.interactionAnchors = [{'d': 'Esomething else'}];
    core.posted.clear();
    await expectLater(keri.interactAid(name: 'Eaid', sealData: [{'d': 'Ewhat was asked'}]), throwsException);
    expect(core.posted, isNot(contains('/api/cesr/encode')));
    expect(await pending(), isEmpty);
  });

  test('a credential anchor that is not the credential issued is not signed', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    core.credentialAnchor = [{'i': 'Esomething else', 's': '0', 'd': 'Esomething else'}];
    core.posted.clear();
    await expectLater(keri.issueCredential(claims: {'a': 'b'}, schemaSaid: 'E'), throwsException);
    expect(core.posted, isNot(contains('/api/cesr/encode')));
    expect(await pending(), isEmpty);
  });

  test('a request refused or answered wrongly is forgotten, one lost in transit is kept', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    core.keyNotHeldHere = true;
    await expectLater(keri.rotateAid(name: 'Eaid'), throwsException);
    expect(await pending(), isEmpty, reason: 'refused');
    core.keyNotHeldHere = false;
    core.foreignNext = KeyManager.keyAt(Bip39.mnemonicToSeed(Bip39.generateMnemonic()), 0).publicKeyEncoded;
    await expectLater(keri.rotateAid(name: 'Eaid'), throwsException);
    expect(await pending(), isEmpty, reason: 'answered with something that is not the rotation');
    core.foreignNext = null;
    // That rotation, never signed, would lock the identity; the core drops it.
    core.kel.removeLast();
    core.raws.removeLast();
    core.dropsRequestsTo = '/api/interact';
    await expectLater(keri.interactAid(name: 'Eaid'), throwsA(isA<http.ClientException>()));
    final kept = await pending();
    expect(kept, hasLength(1), reason: 'lost in transit: the core may have added it');
    expect(kept.single['s'], isNull);
  });

  test('a stranded event, once finished, is no longer written down', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    core.refuseSignatures = true;
    await expectLater(keri.rotateAid(name: 'Eaid'), throwsException);
    expect(await pending(), hasLength(1), reason: 'the stranded rotation is written down');
    core.refuseSignatures = false;
    await keri.signPayload(name: 'Eaid', data: [1]);
    expect(await pending(), isEmpty);
  });

  test('a request whose answer never arrived is recognised only at its own sequence number', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    final seed = Bip39.mnemonicToSeed(words);
    final asked = TheEventsThisDeviceAskedFor();
    final key1 = KeyManager.keyAt(seed, 1).publicKeyEncoded;
    final key2 = KeyManager.keyAt(seed, 2).publicKeyEncoded;
    // Asked for at sequence 1, the answer lost; the core holds the rotation at 2.
    await asked.asking(t: 'rot', aid: 'Eaid', expectedSn: 1, asked: {'key': key1, 'next': key2});
    core.add({'t': 'ixn', 'a': [], 'sig': 'x'});
    core.add(FakeCore.rotation(key1, key2));
    core.posted.clear();
    await expectLater(keri.signPayload(name: 'Eaid', data: [1]), throwsA(isA<AnEventThisDeviceDidNotAskFor>()));
    expect(core.posted, isNot(contains('/api/cesr/encode')));
    // And it is dropped once a signed event holds its place.
    core.kel.removeLast();
    core.raws.removeLast();
    await keri.signPayload(name: 'Eaid', data: [1]);
    expect(await pending(), isEmpty, reason: 'sequence 1 is now held by a signed event');
  });

  test('a request whose answer never arrived is recognised by its keys, at its sequence number', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    final seed = Bip39.mnemonicToSeed(words);
    final asked = TheEventsThisDeviceAskedFor();
    final key1 = KeyManager.keyAt(seed, 1).publicKeyEncoded;
    final key2 = KeyManager.keyAt(seed, 2).publicKeyEncoded;
    await asked.asking(t: 'rot', aid: 'Eaid', expectedSn: 1, asked: {'key': key1, 'next': key2});
    // The rotation at 1 reveals the key asked for but commits to another.
    final attacker = KeyManager.keyAt(Bip39.mnemonicToSeed(Bip39.generateMnemonic()), 0).publicKeyEncoded;
    core.add(FakeCore.rotation(key1, attacker));
    core.posted.clear();
    await expectLater(keri.signPayload(name: 'Eaid', data: [1]), throwsA(isA<AnEventThisDeviceDidNotAskFor>()));
    expect(core.posted, isNot(contains('/api/cesr/encode')));
    // The rotation it did ask for is finished.
    core.kel.removeLast();
    core.raws.removeLast();
    core.add(FakeCore.rotation(key1, key2));
    await keri.signPayload(name: 'Eaid', data: [1]);
    expect(core.kel.last['sig'], isNotNull);
  });

  test('requests written down at the same moment are all kept', () async {
    final asked = TheEventsThisDeviceAskedFor();
    await Future.wait([for (var i = 0; i < 20; i++) asked.asking(t: 'ixn', aid: 'Eaid', expectedSn: i)]);
    expect(await pending(), hasLength(20), reason: 'each write read the list another was writing');
  });

  test('an event this device did not ask for is signed only once the person approves it', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    final seed = Bip39.mnemonicToSeed(words);
    core.add({'t': 'ixn', 'a': [{'d': 'Emade on another of their devices'}]});
    final ixn = core.kel.last;
    final keys = TheKeyInForce(core.client(), 'http://core.test');
    final awaiting = await keys.eventsAwaitingApproval(seed);
    expect(awaiting.map((e) => e['d']), [ixn['d']]);
    await expectLater(keri.signPayload(name: 'Eaid', data: [1]), throwsA(isA<AnEventThisDeviceDidNotAskFor>()),
        reason: 'the identity is locked until somebody acts');
    await keys.signApprovedEvent(seed, sequenceNumber: ixn['s'] as String, digest: ixn['d'] as String);
    expect(core.kel.last['sig'], isNotNull);
    await keri.signPayload(name: 'Eaid', data: [1]);

    // Approval does not lift the rotation checks.
    final attacker = KeyManager.keyAt(Bip39.mnemonicToSeed(Bip39.generateMnemonic()), 0).publicKeyEncoded;
    core.add(FakeCore.rotation(KeyManager.keyAt(seed, 1).publicKeyEncoded, attacker));
    core.posted.clear();
    await expectLater(
        keys.signApprovedEvent(seed, sequenceNumber: core.kel.last['s'] as String, digest: core.kel.last['d'] as String),
        throwsA(predicate((e) => '$e'.contains('not to the next key'))));
    expect(core.posted, isNot(contains('/api/cesr/encode')));
  });

  test('the core\'s own post-quantum commitment and messaging keys are signed only where it was given the phrase',
      () async {
    // What the real core adds of its own, for a key it derives itself.
    core.addsItsOwn = true;
    await expectLater(keri.inceptAid(name: 'Eaid', code: words.join(' ')),
        throwsA(predicate((e) => '$e'.contains('was not given this phrase'))),
        reason: 'the app did not hand this core its phrase');
    expect(core.posted, isNot(contains('/api/cesr/encode')));

    core = FakeCore()..addsItsOwn = true;
    keri = LocalCoreKeriService(baseUrl: 'http://core.test', client: core.client(), theCoreWasGivenThisPhrase: true);
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    expect(core.kel.first['sig'], isNotNull, reason: 'the app handed this core its phrase');
  });

  test('a founding that differs from the one asked for in anything else is never signed', () async {
    final stranger = KeyManager.keyAt(Bip39.mnemonicToSeed(Bip39.generateMnemonic()), 0).publicKeyEncoded;
    final cases = <String, Map<String, dynamic> Function(Map<String, dynamic>)>{
      'a third commitment': (f) => {...f, 'n': [...f['n'] as List, 'Eanother']},
      'a first commitment to another key': (f) => {...f, 'n': [FakeCore.commitmentTo(stranger), ...(f['n'] as List).skip(1)]},
      'another key': (f) => {...f, 'k': [stranger]},
      'a signing threshold of two': (f) => {...f, 'kt': '2'},
      'a next threshold of two': (f) => {...f, 'nt': '2'},
      'a configuration trait': (f) => {...f, 'c': ['EO']},
      'a second anchor': (f) => {...f, 'a': [...f['a'] as List, {'d': 'Esomething'}]},
      'an anchor that is not a keyset': (f) => {...f, 'a': [{'d': 'Esomething'}]},
      'a keyset with something more': (f) => {...f, 'a': [{...FakeCore.keysetAnchor, 'x': 1}]},
    };
    for (final MapEntry(key: what, value: change) in cases.entries) {
      FlutterSecureStorage.setMockInitialValues({});
      SharedPreferences.setMockInitialValues({});
      await SecureKeyStore.saveMnemonic(words);
      core = FakeCore()
        ..addsItsOwn = true
        ..changeFounding = change;
      keri = LocalCoreKeriService(baseUrl: 'http://core.test', client: core.client(), theCoreWasGivenThisPhrase: true);
      await expectLater(keri.inceptAid(name: 'Eaid', code: words.join(' ')), throwsException, reason: what);
      expect(core.posted, isNot(contains('/api/cesr/encode')), reason: 'a founding with $what was signed');
    }
  });

  test('a rotation whose answer was lost after the core added it is finished later, without approval', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    core.dropsAnswersFrom = '/api/rotation';
    await expectLater(keri.rotateAid(name: 'Eaid'), throwsA(isA<http.ClientException>()));
    expect(core.kel.last['t'], 'rot');
    expect(core.kel.last['sig'], isNull, reason: 'added, and its answer never arrived');
    core.dropsAnswersFrom = null;
    await keri.signPayload(name: 'Eaid', data: [1]);
    expect(core.kel.last['sig'], isNotNull, reason: 'recognised as asked for and finished');
    expect(await pending(), isEmpty);
  });

  test('a founding that is not a founding at sequence zero is never signed', () async {
    for (final change in <Map<String, dynamic> Function(Map<String, dynamic>)>[
      (f) => {...f, 't': 'dip'},
      (f) => {...f, 'd': 'Esomethingelse'},
    ]) {
      FlutterSecureStorage.setMockInitialValues({});
      SharedPreferences.setMockInitialValues({});
      await SecureKeyStore.saveMnemonic(words);
      core = FakeCore()..changeFounding = change;
      keri = LocalCoreKeriService(baseUrl: 'http://core.test', client: core.client());
      await expectLater(keri.inceptAid(name: 'Eaid', code: words.join(' ')), throwsException);
      expect(core.posted, isNot(contains('/api/cesr/encode')));
    }
    // And numbered one past zero.
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
    await SecureKeyStore.saveMnemonic(words);
    core = FakeCore()..skipsASequenceNumber = true;
    keri = LocalCoreKeriService(baseUrl: 'http://core.test', client: core.client());
    await expectLater(keri.inceptAid(name: 'Eaid', code: words.join(' ')), throwsException);
    expect(core.posted, isNot(contains('/api/cesr/encode')));
  });

  test('a stranded founding committing to one more key than this core may add is not finished', () async {
    final seed = Bip39.mnemonicToSeed(words);
    final key0 = KeyManager.keyAt(seed, 0).publicKeyEncoded;
    final key1 = KeyManager.keyAt(seed, 1).publicKeyEncoded;
    // This device asked for this founding, and the answer never arrived.
    await TheEventsThisDeviceAskedFor().asking(t: 'icp', expectedSn: 0, asked: {'key': key0, 'next': key1});
    core.add({
      't': 'icp', 'kt': '1', 'k': [key0], 'nt': '1', 'n': [FakeCore.commitmentTo(key1), 'Eanothermachineskey'],
      'bt': '0', 'b': [], 'c': [], 'a': [],
    });
    core.posted.clear();
    await expectLater(keri.signPayload(name: 'Eaid', data: [1]), throwsA(predicate((e) => '$e'.contains('was not given'))));
    expect(core.posted, isNot(contains('/api/cesr/encode')));
  });

  test('a rotation or interaction the core numbers wrongly is not signed', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    core.skipsASequenceNumber = true;
    core.posted.clear();
    await expectLater(keri.rotateAid(name: 'Eaid'), throwsException);
    expect(core.posted, isNot(contains('/api/cesr/encode')));
    core.kel.removeLast();
    core.raws.removeLast();
    await expectLater(keri.interactAid(name: 'Eaid'), throwsException);
    expect(core.posted, isNot(contains('/api/cesr/encode')));
  });

  test('a credential anchor of another identity, or numbered wrongly, is not signed', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    core.anchorsAs = 'Eother';
    core.posted.clear();
    await expectLater(keri.issueCredential(claims: {'a': 'b'}, schemaSaid: 'E'), throwsException);
    expect(core.posted, isNot(contains('/api/cesr/encode')));
    core.kel.removeLast();
    core.raws.removeLast();
    core.anchorsAs = null;
    core.skipsASequenceNumber = true;
    await expectLater(keri.issueCredential(claims: {'a': 'b'}, schemaSaid: 'E'), throwsException);
    expect(core.posted, isNot(contains('/api/cesr/encode')));
  });

  test('an interaction whose answer never arrived is recognised only by the anchors asked for', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    await TheEventsThisDeviceAskedFor().asking(t: 'ixn', aid: 'Eaid', expectedSn: 1, asked: {
      'anchors': [{'d': 'Easked'}]
    });
    core.add({'t': 'ixn', 'a': [{'d': 'Esomethingelse'}]});
    core.posted.clear();
    await expectLater(keri.signPayload(name: 'Eaid', data: [1]), throwsA(isA<AnEventThisDeviceDidNotAskFor>()));
    expect(core.posted, isNot(contains('/api/cesr/encode')));
    core.kel.removeLast();
    core.raws.removeLast();
    core.add({'t': 'ixn', 'a': [{'d': 'Easked'}]});
    await keri.signPayload(name: 'Eaid', data: [1]);
    expect(core.kel.last['sig'], isNotNull);
  });

  test('a request is forgotten once the core has signed its event itself', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    await keri.issueCredential(claims: {'a': 'b'}, schemaSaid: 'E');
    expect(await pending(), hasLength(1), reason: 'the anchor is written down until it is signed');
    core.kel.last['sig'] = 'signed by the core';
    await keri.signPayload(name: 'Eaid', data: [1]);
    expect(await pending(), isEmpty);
  });

  test('approval signs only an interaction, founding or rotation still waiting for its signature', () async {
    await keri.inceptAid(name: 'Eaid', code: words.join(' '));
    final seed = Bip39.mnemonicToSeed(words);
    final keys = TheKeyInForce(core.client(), 'http://core.test');
    // Already signed.
    await expectLater(
        keys.signApprovedEvent(seed, sequenceNumber: '0', digest: 'Eaid'), throwsA(predicate((e) => '$e'.contains('not waiting'))));
    for (final t in ['dip', 'drt']) {
      core.add({...FakeCore.rotation(KeyManager.keyAt(seed, 1).publicKeyEncoded, KeyManager.keyAt(seed, 2).publicKeyEncoded), 't': t});
      core.posted.clear();
      await expectLater(
          keys.signApprovedEvent(seed, sequenceNumber: core.kel.last['s'] as String, digest: core.kel.last['d'] as String),
          throwsException, reason: t);
      expect(core.posted, isNot(contains('/api/cesr/encode')), reason: t);
      core.kel.removeLast();
      core.raws.removeLast();
    }
  });
}
