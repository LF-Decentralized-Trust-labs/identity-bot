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

// A core that keeps a key log the way the real one does: founding puts the key
// it is handed in force, a rotation puts the new key in force, an interaction
// changes no key. It outlives any one LocalCoreKeriService, as the real core
// outlives the app talking to it.
//
// Like the real core it records a signature over an event only if it verifies
// under the key that event is checked against, and records the same one again
// without complaint.
class FakeCore {
  final kel = <Map<String, dynamic>>[];
  final sent = <String, Map<String, dynamic>>{};
  final List<int> eventBytes;
  bool refuseSignatures = false;
  FakeCore(this.eventBytes);

  // The key an event at [sn] is checked against: the one in force after it.
  String keyFor(int sn) =>
      (kel.sublist(0, sn + 1).lastWhere((e) => e['t'] != 'ixn')['k'] as List).first as String;

  String? get currentKey =>
      (kel.lastWhere((e) => e['t'] != 'ixn')['k'] as List).first as String;

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
                    'raw_events_b64': [for (final _ in kel) base64Encode(eventBytes)],
                    'sequence_number': kel.length - 1,
                    'event_count': kel.length,
                  }),
                  200);
          }
          return http.Response('{}', 404);
        }
        final body = jsonDecode(req.body) as Map<String, dynamic>;
        sent[req.url.path] = body;
        final sn = '${kel.length}';
        switch (req.url.path) {
          case '/api/inception':
            kel.add({'t': 'icp', 's': sn, 'k': [body['public_key']]});
          case '/api/rotation':
            kel.add({'t': 'rot', 's': sn, 'k': [body['new_public_key']]});
          case '/api/interact':
          case '/api/credential/issue':
            kel.add({'t': 'ixn', 's': sn});
          case '/api/cesr/encode':
            // Carries the raw signature through, so the core can check it.
            return http.Response(jsonEncode({'cesr_sig': body['raw_sig_b64']}), 200);
          case '/api/events/signature':
            final at = body['sequence_number'] as int;
            final sig = base64Decode(body['cesr_signature'] as String);
            if (refuseSignatures || at >= kel.length ||
                !ed.verify(ed.PublicKey(rawOf(keyFor(at))), Uint8List.fromList(eventBytes), sig)) {
              return http.Response(jsonEncode({'error': 'That signature does not cover this event'}), 400);
            }
            kel[at]['sig'] = body['cesr_signature'];
            return http.Response(jsonEncode({'status': 'signed'}), 200);
          default:
            return http.Response('{}', 200);
        }
        final raw = base64Encode(eventBytes);
        return http.Response(
            jsonEncode({
              'aid': 'Eaid',
              'raw_bytes_b64': raw,
              'ixn_raw_bytes_b64': raw,
              'sequence_number': kel.length - 1,
            }),
            200);
      });
}

void main() {
  final words = Bip39.generateMnemonic();
  final rotationEvent = utf8.encode('{"t":"rot","s":"1"}');

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
    core = FakeCore(rotationEvent);
    sent = core.sent;
    keri = LocalCoreKeriService(baseUrl: 'http://core.test', client: core.client());
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
    expect(verifiesUnder(inForce, rotationEvent, lastSignature()), isTrue,
        reason: 'an interaction after a rotation is signed by the key the log says is in force');

    final data = utf8.encode('after the rotation');
    final result = await keri.signPayload(name: 'Eaid', data: data);
    expect(result.publicKey, inForce,
        reason: 'the key reported is the key in force, not the founding key');
    expect(verifiesUnder(inForce, data, base64Decode(result.signature)), isTrue);

    await keri.issueCredential(claims: {'role': 'engineer'}, schemaSaid: 'Eschema');
    expect(verifiesUnder(inForce, rotationEvent, lastSignature()), isTrue,
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
    expect(verifiesUnder(second['new_public_key'] as String, rotationEvent, lastSignature()), isTrue,
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
    core.kel.add({'t': 'rot', 's': '1', 'k': [KeyManager.keyAt(Bip39.mnemonicToSeed(Bip39.generateMnemonic()), 1).publicKeyEncoded]});
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
          verifiesUnder(core.keyFor(sn), rotationEvent, base64Decode(event['sig'] as String)), isTrue,
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
    expect(log.rawEventsB64, [base64Encode(rotationEvent), base64Encode(rotationEvent)]);
    expect(log.sequenceNumber, 1);
    expect(log.eventCount, 2);
    expect(log.establishmentEvents.last['k'], [core.currentKey]);
  });
}
