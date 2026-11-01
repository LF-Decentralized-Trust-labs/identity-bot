import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/local_core_keri_service.dart';
import 'package:agent_client/services/keri_service.dart';
import 'package:agent_client/services/owner_signing_client.dart';
import 'package:agent_client/services/secure_key_store.dart';
import 'package:agent_client/services/the_event_this_device_expects.dart';
import 'package:agent_client/services/the_events_this_device_asked_for.dart';
import 'package:agent_client/services/the_events_this_device_signed.dart';
import 'package:agent_client/services/the_key_events_this_device_makes.dart';
import 'package:agent_client/services/the_key_in_force.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

import 'support/kel_events.dart';
import 'support/the_core.dart';

// The raw 32 bytes behind a qb64 key with a one-character code.
List<int> rawOf(String qb64) =>
    base64Url.decode('A${qb64.substring(1)}').sublist(1);

Map<String, dynamic> eventIn(List<int> raw) =>
    jsonDecode(utf8.decode(raw)) as Map<String, dynamic>;

// The fields each event type carries after `v`, in the order it serialises
// them.
const _order = {
  'icp': ['t', 'd', 'i', 's', 'kt', 'k', 'nt', 'n', 'bt', 'b', 'c', 'a'],
  'rot': ['t', 'd', 'i', 's', 'p', 'kt', 'k', 'nt', 'n', 'bt', 'br', 'ba', 'a'],
  'ixn': ['t', 'd', 'i', 's', 'p', 'a'],
};

// A core that keeps a key log the way the real one does. It outlives any one
// LocalCoreKeriService, as the real core outlives the app talking to it.
//
// Every event it holds is a real KERI 1.0 event (saidified), so the core's
// own parser, which the app runs before signing, reads it as the real core's
// would.
//
// An app holding the keys has the core prepare an event
// (/api/events/prepare): the core builds it from what was asked and adds
// nothing. The app checks the bytes, signs them and commits them
// (/api/events/commit), and only then does the core add the event, after
// checking the signature under the key the event is checked against, as the
// real core does. The tamper knobs below change what the core PREPARES, so
// that it is the app's check that refuses it.
//
// Events an earlier version of the app left unsigned, before events were
// prepared and committed, are seeded into the log directly ([add]) and are
// signed late through /api/events/signature, which the core still takes.
class FakeCore {
  final kel = <Map<String, dynamic>>[];
  // The bytes each event was published as, beside it.
  final raws = <List<int>>[];
  // The bytes of every event the core prepared, in order.
  final prepared = <List<int>>[];
  final sent = <String, Map<String, dynamic>>{};
  final posted = <String>[];
  // Refuses every signature, whether committed with an event or recorded
  // against one already in the log.
  bool refuseSignatures = false;
  // Refuses to prepare anything, as a core answering someone who is not the
  // owner does.
  bool refusesToPrepare = false;
  // Rewrites the bytes served for an unsigned event, as a core lying about
  // what an event is would.
  Map<String, dynamic> Function(Map<String, dynamic>)? tamper;
  // Makes the founding or rotation the core prepares commit to somebody
  // else's next key.
  String? foreignNext;
  // What the core anchors when it issues a credential, if not the credential.
  List<Object?>? credentialAnchor;
  // Rewrites the rotation or interaction the core prepares, or the anchors of
  // an interaction.
  Map<String, dynamic> Function(Map<String, dynamic>)? changeRotation;
  Map<String, dynamic> Function(Map<String, dynamic>)? changeInteraction;
  List<Object?>? interactionAnchors;
  // A path whose request fails in transit, before or after the core acts on it.
  String? dropsRequestsTo;
  String? dropsAnswersFrom;
  // Numbers the next event one past where it belongs.
  bool skipsASequenceNumber = false;
  // Writes another identifier into the credential anchor it builds.
  String? anchorsAs;
  // Adds to a founding it prepares a post-quantum next-key commitment and an
  // anchor of messaging keys of its own, as the core once did.
  bool addsItsOwn = false;
  // Rewrites the founding the core prepares.
  Map<String, dynamic> Function(Map<String, dynamic>)? changeFounding;
  // Writes another digest into the event it prepares, so the bytes no longer
  // digest to what they say.
  bool misdigests = false;

  static const keysetAnchor = {
    'ia': 'IA-HYBRID-1',
    'ka': ['Ckem'],
    'sa': ['Dsig']
  };
  // Answers 404 to a signature, as a core that does not hold the event does.
  bool forgetsEvents = false;

  String get aid => kel.first['i'] as String;

  // The key an event at [sn] is checked against: the one in force at it.
  String keyFor(int sn) =>
      (kel.sublist(0, sn + 1).lastWhere((e) => e['t'] != 'ixn')['k'] as List)
          .first as String;

  String? get currentKey =>
      (kel.lastWhere((e) => e['t'] != 'ixn')['k'] as List).first as String;

  List<int> raw(int sn) => raws[sn];

  // The signature recorded over the event at [sn].
  Uint8List sigAt(int sn) => base64Decode(kel[sn]['sig'] as String);

  // The fields of [event] in the order its type serialises them; a type
  // without an order of its own here (a delegated one) is laid out as a
  // rotation is.
  static Map<String, Object?> ordered(Map<String, dynamic> event) {
    final order = _order[event['t']] ?? _order['rot']!;
    return {
      for (final f in order)
        if (event.containsKey(f)) f: event[f]
    };
  }

  // Appends an event, laid out as the engine lays one out, at the tip: the
  // identifier, place and prior are the log's own. [signedBy], a 32-byte
  // signing seed, signs it; otherwise it is unsigned, as an event an earlier
  // version of the app left.
  void add(Map<String, dynamic> event, {Uint8List? signedBy}) {
    final sn = (kel.length + (skipsASequenceNumber ? 1 : 0)).toRadixString(16);
    final founding = event['t'] == 'icp';
    final raw = saidified(ordered({
      ...event,
      'd': '',
      'i': founding ? '' : aid,
      's': sn,
      if (!founding) 'p': kel.last['d'],
    }));
    _append(
        raw,
        signedBy == null
            ? null
            : base64Encode(
                ed.sign(ed.newKeyFromSeed(signedBy), Uint8List.fromList(raw))));
  }

  void _append(List<int> raw, String? sig) {
    raws.add(raw);
    kel.add({...eventIn(raw), if (sig != null) 'sig': sig});
  }

  void removeLast() {
    kel.removeLast();
    raws.removeLast();
  }

  // A founding as an earlier version asked for one: one key, committing to
  // one next key.
  static Map<String, dynamic> oldFounding(String key, String next,
          {List<Object?> n = const [], List<Object?> a = const []}) =>
      {
        't': 'icp',
        'kt': '1',
        'k': [key],
        'nt': '1',
        'n': [TheKeyInForce.commitmentTo(next), ...n],
        'bt': '0',
        'b': [],
        'c': [],
        'a': a,
      };

  // A rotation to [key], committing to [next], as an earlier version asked
  // for one.
  static Map<String, dynamic> rotation(String key, String next) => {
        't': 'rot',
        'kt': '1',
        'k': [key],
        'nt': '1',
        'n': [TheKeyInForce.commitmentTo(next)],
        'bt': '0',
        'br': [],
        'ba': [],
        'a': []
      };

  static http.Response _json(Object body, int status) =>
      http.Response(jsonEncode(body), status);

  // The event the core prepares for [body], with the tamper knobs applied.
  http.Response _prepare(Map<String, dynamic> body) {
    if (refusesToPrepare) {
      return _json({
        'error': "Key events are the owner's",
        'details': 'only the owner prepares a key event'
      }, 403);
    }
    final t = body['t'];
    List<Object?> list(Object? v) => [...(v as List? ?? const [])];
    List<Object?> next(Object? n) => [
          for (final (i, c) in list(n).indexed)
            i == 0 && foreignNext != null
                ? TheKeyInForce.commitmentTo(foreignNext!)
                : c
        ];
    Map<String, dynamic> event;
    if (t == 'icp') {
      if (kel.isNotEmpty) {
        return _json(
            {'error': 'Identity already exists', 'details': 'AID: $aid'}, 409);
      }
      event = {
        't': 'icp',
        'd': '',
        'i': '',
        's': skipsASequenceNumber ? '1' : '0',
        'kt': body['kt'] ?? '1',
        'k': list(body['k']),
        'nt': body['nt'] ?? '1',
        'n': [...next(body['n']), if (addsItsOwn) 'E${'P' * 43}'],
        'bt': body['bt'] ?? '0',
        'b': list(body['b']),
        'c': [],
        'a': [...list(body['a']), if (addsItsOwn) keysetAnchor],
      };
      if (changeFounding != null) event = changeFounding!(event);
    } else if (t == 'rot' || t == 'ixn') {
      if (kel.isEmpty) {
        return _json({
          'error': 'There is no identity here to extend',
          'details': 'found one first'
        }, 409);
      }
      if (body['aid'] != aid) {
        return _json({
          'error': "That is not this Identity Agent's identity",
          'details': 'this Identity Agent keeps the log of $aid'
        }, 400);
      }
      final after = body['after'] as Map<String, dynamic>;
      final afterSn = int.parse(after['s'] as String, radix: 16);
      // This core prepares only at the tip.
      if (afterSn != kel.length - 1 || kel.last['d'] != after['d']) {
        return _json({
          'error': 'tip_moved',
          'details': 'the event named is not the tip',
          'tip': {'s': kel.last['s'], 'd': kel.last['d']}
        }, 409);
      }
      final place = {
        't': t,
        'd': '',
        'i': aid,
        's': (afterSn + 1 + (skipsASequenceNumber ? 1 : 0)).toRadixString(16),
        'p': after['d'],
      };
      if (t == 'rot') {
        event = {
          ...place,
          'kt': body['kt'] ?? '1',
          'k': list(body['k']),
          'nt': body['nt'] ?? '1',
          'n': next(body['n']),
          'bt': body['bt'] ?? '0',
          'br': list(body['br']),
          'ba': list(body['ba']),
          'a': list(body['a']),
        };
        if (changeRotation != null) event = changeRotation!(event);
      } else {
        event = {...place, 'a': interactionAnchors ?? list(body['a'])};
        if (changeInteraction != null) event = changeInteraction!(event);
      }
    } else {
      return _json(
          {'error': 'Unknown event type', 'details': 't is icp, rot or ixn'},
          400);
    }
    var raw = saidified(event);
    if (misdigests) {
      final e = eventIn(raw)..['d'] = 'E${'A' * 43}';
      raw = utf8.encode(jsonEncode(e));
    }
    prepared.add(raw);
    return _json({'raw_b64': base64Encode(raw)}, 200);
  }

  // Adds an event the app signed, as the real core does: only the bytes of a
  // well-formed event, at the tip, following it, with no unsigned event
  // before it, and signed by the key it is checked against.
  http.Response _commit(Map<String, dynamic> body) {
    final raw = base64Decode(body['raw_b64'] as String);
    final ev = eventIn(raw);
    final founding = ev['t'] == 'icp';
    // The bytes are an event whose digest is its own.
    final blank = {...ev, 'd': '', if (founding) 'i': ''}..remove('v');
    if (utf8.decode(saidified(blank)) != utf8.decode(raw)) {
      return _json(
          {'error': 'The event does not parse', 'details': 'digest'}, 400);
    }
    final sn = int.parse(ev['s'] as String, radix: 16);
    if (!founding && (kel.isEmpty || ev['i'] != aid)) {
      return _json({
        'error': "That is not this Identity Agent's identity",
        'details':
            'an event is committed only to the log of the identity kept here'
      }, 400);
    }
    final sigs = [for (final s in body['sigs'] as List? ?? const []) '$s'];
    bool verifies(String key) =>
        sigs.isNotEmpty &&
        ed.verify(ed.PublicKey(rawOf(key)), Uint8List.fromList(raw),
            base64Decode(sigs.first));
    if (sn < kel.length) {
      if (kel[sn]['d'] != ev['d']) {
        return _json({
          'error': 'place_taken',
          'details': 'another event holds that place',
          's': kel[sn]['s'],
          'd': kel[sn]['d']
        }, 409);
      }
      return _json(
          {'status': 'already_recorded', 's': ev['s'], 'd': ev['d']}, 200);
    }
    if (sn != kel.length || (!founding && ev['p'] != kel.last['d'])) {
      return _json({'error': 'tip_moved', 'details': 'not at the tip'}, 409);
    }
    final unsigned = [
      for (final e in kel)
        if (e['sig'] == null) e['s']
    ];
    if (unsigned.isNotEmpty) {
      return _json({
        'error': 'unsigned_history',
        'details': 'earlier events are unsigned',
        'unsigned': unsigned
      }, 409);
    }
    final key = ev['t'] == 'ixn' ? currentKey! : (ev['k'] as List).first;
    if (refuseSignatures || !verifies(key as String)) {
      return _json({
        'error': 'not_authorised',
        'details': 'the signatures do not satisfy the key in force'
      }, 400);
    }
    _append(raw, sigs.first);
    return _json({'status': 'recorded', 's': ev['s'], 'd': ev['d']}, 201);
  }

  http.Client client() => MockClient((req) async {
        if (req.method == 'GET') {
          switch (req.url.path) {
            case '/api/identity':
              return _json(
                  kel.isEmpty
                      ? {'initialized': false}
                      : {'initialized': true, 'aid': aid},
                  200);
            case '/api/kel':
              if (kel.isEmpty || req.url.queryParameters['name'] != aid) {
                return _json({'error': 'no identity named that'}, 500);
              }
              return _json({
                'aid': aid,
                'kel': [
                  for (final e in kel) {...e}..remove('sig')
                ],
                'raw_events_b64': [
                  for (var i = 0; i < kel.length; i++)
                    base64Encode(tamper != null && kel[i]['sig'] == null
                        ? utf8.encode(jsonEncode(tamper!(eventIn(raws[i]))))
                        : raws[i]),
                ],
                'sequence_number': kel.length - 1,
                'event_count': kel.length,
                'signed': [for (final e in kel) e['sig'] != null],
              }, 200);
          }
          return http.Response('{}', 404);
        }
        final body = jsonDecode(req.body) as Map<String, dynamic>;
        sent[req.url.path] = body;
        posted.add(req.url.path);
        if (req.url.path == dropsRequestsTo) {
          throw http.ClientException('the connection dropped');
        }
        final http.Response answer;
        switch (req.url.path) {
          case '/api/keystore/messaging-seed':
            answer = _json({'status': 'stored'}, 200);
          case '/api/events/prepare':
            answer = _prepare(body);
          case '/api/events/commit':
            answer = _commit(body);
          case '/api/credential/issue':
            add({
              't': 'ixn',
              'a': credentialAnchor ??
                  [
                    {'i': 'Ecredential', 's': '0', 'd': 'Ecredential'}
                  ]
            });
            if (anchorsAs != null) {
              final e = eventIn(raws.last)..['i'] = anchorsAs;
              removeLast();
              _append(saidified({...e}..remove('v')), null);
            }
            final raw = base64Encode(raws.last);
            answer = _json({
              'aid': aid,
              'raw_bytes_b64': raw,
              'ixn_raw_bytes_b64': raw,
              'acdc_said': 'Ecredential',
              'sequence_number': kel.length - 1,
            }, 200);
          case '/api/cesr/encode':
            // Carries the raw signature through, so the core can check it.
            answer = _json({'cesr_sig': body['raw_sig_b64']}, 200);
          case '/api/events/signature':
            // An event an earlier version added and left unsigned, signed late.
            if (forgetsEvents) {
              return _json({'error': 'No such event'}, 404);
            }
            final at = body['sequence_number'] as int;
            final sig = base64Decode(body['cesr_signature'] as String);
            if (refuseSignatures ||
                at >= kel.length ||
                !ed.verify(ed.PublicKey(rawOf(keyFor(at))),
                    Uint8List.fromList(raws[at]), sig)) {
              return _json(
                  {'error': 'That signature does not cover this event'}, 400);
            }
            kel[at]['sig'] = body['cesr_signature'];
            answer = _json({'status': 'signed'}, 200);
          default:
            answer = http.Response('{}', 200);
        }
        if (req.url.path == dropsAnswersFrom) {
          throw http.ClientException('the answer was lost');
        }
        return answer;
      });
}

void main() {
  final words = Bip39.generateMnemonic();
  final seed = Bip39.mnemonicToSeed(words);
  String key(int i) => KeyManager.keyAt(seed, i).publicKeyEncoded;
  Uint8List signer(int i) => KeyManager.signingSeed(seed, index: i);
  String strangersKey(int i) =>
      KeyManager.keyAt(Bip39.mnemonicToSeed(Bip39.generateMnemonic()), i)
          .publicKeyEncoded;

  late KeyMath km;
  late FakeCore core;
  late Map<String, Map<String, dynamic>> sent;
  late LocalCoreKeriService keri;

  setUpAll(() async {
    km = await keyMathOf(await buildTheCore('rotation-core'));
  });

  LocalCoreKeriService serviceOver(FakeCore c,
          {bool theCoreWasGivenThisPhrase = false}) =>
      LocalCoreKeriService(
          baseUrl: 'http://core.test',
          client: c.client(),
          keyMath: km,
          theCoreWasGivenThisPhrase: theCoreWasGivenThisPhrase);

  Future<void> freshDevice() async {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
    await SecureKeyStore.saveMnemonic(words);
  }

  // The signature most recently handed to the core to CESR-encode.
  Uint8List lastSignature() =>
      base64Decode(sent['/api/cesr/encode']!['raw_sig_b64'] as String);

  bool verifiesUnder(String qb64, List<int> data, List<int> sig) => ed.verify(
      ed.PublicKey(rawOf(qb64)),
      Uint8List.fromList(data),
      Uint8List.fromList(sig));

  Future<List<Reservation>> reservations(String aid) =>
      TheEventsThisDeviceSigned().unfinished(aid);

  // Nothing was signed as an event: no signature was made or sent for one,
  // and no place was reserved for anything the core prepared.
  Future<void> nothingSigned(FakeCore c, {String? reason}) async {
    for (final path in [
      '/api/cesr/encode',
      '/api/events/commit',
      '/api/events/signature'
    ]) {
      expect(c.posted, isNot(contains(path)), reason: reason);
    }
    for (final raw in c.prepared) {
      expect(await reservations(eventIn(raw)['i'] as String), isEmpty,
          reason: reason);
    }
  }

  setUp(() async {
    await freshDevice();
    core = FakeCore();
    sent = core.sent;
    keri = serviceOver(core);
  });

  Future<List<Map<String, dynamic>>> pending() async {
    final asked = TheEventsThisDeviceAskedFor();
    return asked.pending(await asked.scope());
  }

  // The founding an earlier version of this app made and signed, by the
  // routes it used then.
  void foundedByAnEarlierVersion(FakeCore c) =>
      c.add(FakeCore.oldFounding(key(0), key(1)), signedBy: signer(0));

  // An event an earlier version asked the core to add, written down as it
  // wrote it, and left unsigned: its answer arrived and the signature never
  // did.
  Future<void> strandedByAnEarlierVersion(FakeCore c,
      Map<String, dynamic> event, Map<String, dynamic> asked) async {
    final record = TheEventsThisDeviceAskedFor();
    final request = await record.asking(
        t: event['t'] as String,
        aid: c.kel.isEmpty ? null : c.aid,
        expectedSn: c.kel.length,
        asked: asked);
    c.add(event);
    await record.added(request,
        aid: c.aid,
        sequenceNumber: c.kel.length - 1,
        digest: c.kel.last['d'] as String);
  }

  test('a rotation names the key founding committed to, and that key signs it',
      () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    final founding = core.kel.single;
    expect((founding['n'] as List).first, await km.nextKeyDigest(key(1)),
        reason: 'the founding commits to the next key of this phrase');

    await keri.rotateAid(name: core.aid);
    final rotation = core.kel[1];
    expect(rotation['k'], [key(1)],
        reason:
            'the new key must be the next key the founding event committed to');
    expect(verifiesUnder(key(1), core.raw(1), core.sigAt(1)), isTrue,
        reason: 'the key the rotation names must be the key that signs it');

    // And the rotation commits to the key after it, derived the same way,
    // and to the post-quantum key of its own generation.
    final pq = await km.postQuantumNext(
        KeyManager.slip10Ed25519(seed, KeyPaths.postQuantum(1)));
    expect(rotation['n'], [await km.nextKeyDigest(key(2)), pq.digest]);
    expect(key(2), isNot(key(1)));
  });

  test('every key in the chain comes from signingSeed', () {
    final keys = KeyManager.generateKeysFromMnemonic(words);
    for (final (index, pair) in [(0, keys.signing), (1, keys.next)]) {
      final fromSeed = ed.public(
          ed.newKeyFromSeed(KeyManager.signingSeed(seed, index: index)));
      expect(pair.publicKey, fromSeed.bytes);
      expect(KeyManager.keyAt(seed, index).publicKey, fromSeed.bytes);
    }
    expect(
        KeyManager.signingSeed(seed), KeyManager.signingSeed(seed, index: 0));
    expect(() => KeyManager.signingSeed(seed, index: -1), throwsArgumentError);
    expect(() => KeyManager.signingSeed(seed, index: 0x80000000),
        throwsArgumentError);
  });

  test('a signature made as the identity reports the key that made it',
      () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    final data = utf8.encode('hello');
    final result = await keri.signPayload(name: 'me', data: data);
    expect(result.publicKey, key(0));
    final k = ed.PublicKey(rawOf(result.publicKey));
    expect(
        ed.verify(k, Uint8List.fromList(data), base64Decode(result.signature)),
        isTrue);
  });

  test(
      'after a rotation, an interaction and a signature are made by the rotated key',
      () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    await keri.rotateAid(name: core.aid);
    final inForce = core.currentKey!;
    expect(inForce, key(1));

    await keri.interactAid(name: core.aid);
    expect(core.kel[2]['t'], 'ixn');
    expect(verifiesUnder(inForce, core.raw(2), core.sigAt(2)), isTrue,
        reason:
            'an interaction after a rotation is signed by the key the log says is in force');

    final data = utf8.encode('after the rotation');
    final result = await keri.signPayload(name: core.aid, data: data);
    expect(result.publicKey, inForce,
        reason: 'the key reported is the key in force, not the founding key');
    expect(
        verifiesUnder(inForce, data, base64Decode(result.signature)), isTrue);

    await keri
        .issueCredential(claims: {'role': 'engineer'}, schemaSaid: 'Eschema');
    expect(verifiesUnder(inForce, core.raw(3), lastSignature()), isTrue,
        reason:
            'the event anchoring a credential is signed by the key in force');
  });

  test(
      'a second rotation reveals the key the first committed to, and commits to the next',
      () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    await keri.rotateAid(name: core.aid);
    await keri.rotateAid(name: core.aid);
    final first = core.kel[1];
    final second = core.kel[2];
    expect((first['n'] as List).first, await km.nextKeyDigest(key(2)));
    expect(second['k'], [key(2)],
        reason: 'the second rotation reveals the key the first committed to');
    expect((second['n'] as List).first, await km.nextKeyDigest(key(3)));
    expect(second['p'], first['d'], reason: 'it follows the first rotation');
    expect(verifiesUnder(key(2), core.raw(2), core.sigAt(2)), isTrue,
        reason: 'the key the second rotation names is the key that signs it');
  });

  test('the key in force is still known after the app restarts', () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    await keri.rotateAid(name: core.aid);

    // A new service against the same core: nothing carried over in memory.
    final restarted = serviceOver(core);
    final data = utf8.encode('after a restart');
    final result = await restarted.signPayload(name: core.aid, data: data);
    expect(result.publicKey, core.currentKey);
    expect(
        verifiesUnder(core.currentKey!, data, base64Decode(result.signature)),
        isTrue);

    await restarted.rotateAid(name: core.aid);
    expect(core.kel.last['k'], [key(2)]);
  });

  test('nothing is signed when the log names a key this phrase does not hold',
      () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    core.add(FakeCore.rotation(strangersKey(1), strangersKey(2)));
    await expectLater(
        keri.signPayload(name: core.aid, data: [1, 2, 3]), throwsException);
  });

  test('a rotation and an interaction end up signed in the key log', () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    await keri.rotateAid(name: core.aid);
    await keri.interactAid(name: core.aid);
    await keri.rotateAid(name: core.aid);
    expect(core.kel.map((e) => e['t']), ['icp', 'rot', 'ixn', 'rot']);
    for (final (sn, event) in core.kel.indexed) {
      expect(event['sig'], isNotNull,
          reason: 'event $sn (${event['t']}) was left unsigned in the log');
      expect(
          verifiesUnder(core.keyFor(sn), core.raw(sn), core.sigAt(sn)), isTrue,
          reason: 'event $sn is signed by the key it is checked against');
      expect(await km.parseEvent(core.raw(sn)), isA<ParsedEvent>(),
          reason: 'event $sn is one the core\'s own parser reads');
    }
    expect(await reservations(core.aid), isEmpty,
        reason: 'every event this device signed was committed');
  });

  test('a rotation whose signature the core refuses says so', () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    core.refuseSignatures = true;
    await expectLater(keri.rotateAid(name: core.aid),
        throwsA(predicate((e) => '$e'.contains('was refused'))));
    await expectLater(keri.interactAid(name: core.aid), throwsException);
    expect(core.kel.map((e) => e['t']), ['icp'],
        reason: 'the core adds no event whose signature it refused');
  });

  test('the key log is read as the list of events the core sends', () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    await keri.rotateAid(name: core.aid);
    final log = await keri.getCurrentKel(name: core.aid);
    expect(log.aid, core.aid);
    expect(log.events.map((e) => e['t']), ['icp', 'rot']);
    expect(log.rawEventsB64,
        [base64Encode(core.raw(0)), base64Encode(core.raw(1))]);
    expect(log.sequenceNumber, 1);
    expect(log.eventCount, 2);
    expect(log.establishmentEvents.last['k'], [core.currentKey]);
  });

  // Replaces "where the core does not hold the key, a rotation says so and
  // signs nothing": the core no longer adds a rotation itself, so the refusal
  // that matters is one to prepare it.
  test('a core that will not prepare an event says why, and nothing is signed',
      () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    core.refusesToPrepare = true;
    core.posted.clear();
    await expectLater(
        keri.rotateAid(name: core.aid),
        throwsA(isA<KeyEventRefused>()
            .having((e) => e.statusCode, 'status', 403)
            .having((e) => e.code, 'code', "Key events are the owner's")));
    await expectLater(
        keri.interactAid(name: core.aid), throwsA(isA<KeyEventRefused>()));
    await nothingSigned(core,
        reason: 'nothing is signed that was never prepared');
    expect(core.kel.map((e) => e['t']), ['icp']);
  });

  test('only the identity held here is rotated with its phrase', () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    core.posted.clear();
    await expectLater(
        keri.rotateAid(name: 'Esomebody-else'), throwsArgumentError);
    expect(core.posted, isNot(contains('/api/events/prepare')));
    expect(core.kel, hasLength(1));
  });

  test('the key is worked out before the event exists', () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    // A log naming a key this phrase does not hold, signed by that key.
    final stranger = Bip39.mnemonicToSeed(Bip39.generateMnemonic());
    core.add(
        FakeCore.rotation(KeyManager.keyAt(stranger, 1).publicKeyEncoded,
            KeyManager.keyAt(stranger, 2).publicKeyEncoded),
        signedBy: KeyManager.signingSeed(stranger, index: 1));
    core.posted.clear();
    await expectLater(keri.interactAid(name: core.aid), throwsException);
    await expectLater(keri.issueCredential(claims: {'a': 'b'}, schemaSaid: 'E'),
        throwsException);
    expect(core.posted, isEmpty,
        reason:
            'nothing is asked of a core whose log this phrase cannot sign for');
  });

  test(
      'an establishment event an earlier version left unsigned is signed the next time the identity signs',
      () async {
    foundedByAnEarlierVersion(core);
    await strandedByAnEarlierVersion(core, FakeCore.rotation(key(1), key(2)),
        {'key': key(1), 'next': key(2)});
    expect(core.kel.last['sig'], isNull,
        reason: 'the rotation is stranded: added and never signed');

    final data = utf8.encode('after the upgrade');
    final result = await keri.signPayload(name: core.aid, data: data);
    expect(core.kel.last['sig'], isNotNull,
        reason: 'the stranded rotation was finished');
    expect(verifiesUnder(key(1), core.raw(1), core.sigAt(1)), isTrue);
    expect(result.publicKey, core.currentKey);

    // And the next rotation, prepared and committed, builds on it.
    await keri.rotateAid(name: core.aid);
    expect(core.kel.last['k'], [key(2)]);
    expect(core.kel.last['p'], core.kel[1]['d']);
  });

  test('a stranded event is finished before a new one is prepared after it',
      () async {
    foundedByAnEarlierVersion(core);
    await strandedByAnEarlierVersion(core, FakeCore.rotation(key(1), key(2)),
        {'key': key(1), 'next': key(2)});
    await keri.interactAid(name: core.aid);
    expect(core.kel.map((e) => e['t']), ['icp', 'rot', 'ixn']);
    expect(core.posted.indexOf('/api/events/signature'),
        lessThan(core.posted.indexOf('/api/events/prepare')),
        reason: 'the core takes no event after an unsigned one');
    expect(verifiesUnder(key(1), core.raw(2), core.sigAt(2)), isTrue);
  });

  test('a request signed as the owner is signed with the key in force',
      () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    await keri.rotateAid(name: core.aid);
    final reader = seedFromMnemonic(
      () async => words,
      (m) => Bip39.mnemonicToSeed(m.split(' ')),
      TheKeyInForce(core.client(), 'http://core.test').index,
    );
    final ownerSeed = await reader();
    expect(KeyManager.keyAt(seed, 1).publicKey,
        ed.public(ed.newKeyFromSeed(ownerSeed!)).bytes,
        reason:
            'after a rotation the owner is the rotated key, not the founding one');
  });

  test('an answer that is not a key log is refused, not read as an empty one',
      () {
    expect(() => KeyEventLog.fromJson({'kel': []}), throwsFormatException);
    expect(() => KeyEventLog.fromJson({'aid': 'Eaid'}), throwsFormatException);
    expect(() => KeyEventLog.fromJson({'aid': 'Eaid', 'kel': 'x'}),
        throwsFormatException);
    expect(KeyEventLog.fromJson({'aid': 'Eaid', 'kel': []}).events, isEmpty);
  });

  test('an interaction left unsigned is signed with the key in force at it',
      () async {
    foundedByAnEarlierVersion(core);
    core.add(FakeCore.rotation(key(1), key(2)), signedBy: signer(1));
    await strandedByAnEarlierVersion(
        core, {'t': 'ixn', 'a': []}, {'anchors': []});

    await keri.signPayload(name: core.aid, data: [1, 2, 3]);
    final ixn = core.kel.length - 1;
    expect(core.kel[ixn]['sig'], isNotNull,
        reason: 'the stranded interaction was finished');
    expect(verifiesUnder(key(1), core.raw(ixn), core.sigAt(ixn)), isTrue,
        reason:
            'signed by the key in force at it: the rotated key, not the founding one');
  });

  test('bytes that differ from a stranded event in one field are not signed',
      () async {
    final cases = <String, Map<String, dynamic> Function(Map<String, dynamic>)>{
      'its digest': (e) => {...e, 'd': 'Eanother'},
      'its keys': (e) => {
            ...e,
            'k': [strangersKey(1)]
          },
      'its sequence number': (e) => {...e, 's': 'f'},
      'its identifier': (e) => {...e, 'i': 'Eother'},
    };
    for (final MapEntry(key: what, value: change) in cases.entries) {
      await freshDevice();
      core = FakeCore();
      keri = serviceOver(core);
      foundedByAnEarlierVersion(core);
      await strandedByAnEarlierVersion(core, FakeCore.rotation(key(1), key(2)),
          {'key': key(1), 'next': key(2)});
      core.tamper = change;
      core.posted.clear();
      await expectLater(
          keri.signPayload(name: core.aid, data: [1]), throwsException,
          reason: what);
      expect(core.posted, isNot(contains('/api/cesr/encode')),
          reason: 'bytes that differ from the event in $what are never signed');
      expect(core.kel.last['sig'], isNull, reason: what);
    }
  });

  test(
      'bytes the core prepares that differ from the event in one field are not signed',
      () async {
    final other = 'E${'O' * 43}';
    final cases = <String, void Function(FakeCore)>{
      'its digest': (c) => c.misdigests = true,
      'its keys': (c) => c.changeRotation = (r) => {
            ...r,
            'k': [strangersKey(1)]
          },
      'its sequence number': (c) => c.skipsASequenceNumber = true,
      'its identifier': (c) => c.changeRotation = (r) => {...r, 'i': other},
      'its prior': (c) => c.changeRotation = (r) => {...r, 'p': other},
    };
    for (final MapEntry(key: what, value: tamper) in cases.entries) {
      await freshDevice();
      core = FakeCore();
      keri = serviceOver(core);
      await keri.inceptAid(name: 'me', code: words.join(' '));
      tamper(core);
      core.posted.clear();
      await expectLater(
          keri.rotateAid(name: core.aid), throwsA(isA<NotTheEventExpected>()),
          reason: what);
      await nothingSigned(core,
          reason: 'a rotation that differs in $what was signed');
      expect(core.kel, hasLength(1), reason: what);
    }
    // An interaction of another identity.
    await freshDevice();
    core = FakeCore();
    keri = serviceOver(core);
    await keri.inceptAid(name: 'me', code: words.join(' '));
    core.changeInteraction = (e) => {...e, 'i': other};
    core.posted.clear();
    await expectLater(
        keri.interactAid(name: core.aid), throwsA(isA<NotTheEventExpected>()));
    await nothingSigned(core);
  });

  test(
      'a stranded event the core will not take a signature for stops signing, and says why',
      () async {
    foundedByAnEarlierVersion(core);
    await strandedByAnEarlierVersion(
        core, {'t': 'ixn', 'a': []}, {'anchors': []});
    core.forgetsEvents = true;
    await expectLater(keri.signPayload(name: core.aid, data: [1]),
        throwsA(isA<StrandedEventCannotBeFinished>()));
  });

  test(
      'the key in force is read through a plain client, never the owner-signing one',
      () {
    final signing = OwnerSigningClient(
        agentOrigin: 'http://core.test', ownerSeed: () async => null);
    expect(
        () => TheKeyInForce(signing, 'http://core.test'), throwsArgumentError);
    signing.close();
  });

  test('a credential is not asked for where there is no phrase to sign it with',
      () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    await SecureKeyStore.clearMnemonic();
    core.posted.clear();
    await expectLater(
        keri.issueCredential(claims: {'a': 'b'}, schemaSaid: 'E'),
        throwsA(predicate((e) =>
            '$e'.contains('No identity keys found in secure storage.'))));
    await expectLater(
        keri.presentCredential(acdcSaid: 'Ex', holderAid: core.aid),
        throwsA(predicate((e) =>
            '$e'.contains('No identity keys found in secure storage.'))));
    expect(core.posted, isEmpty,
        reason: 'nothing is asked of the core that could not then be signed');
  });

  test(
      'a rotation the core added on its own, committing to its own key, is never signed',
      () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    // Reveals this phrase's key 1, as a real rotation would, and commits to
    // the attacker's key, marked unsigned so the device would finish it.
    core.add(FakeCore.rotation(key(1), strangersKey(0)));
    core.posted.clear();
    await expectLater(keri.signPayload(name: core.aid, data: [1]),
        throwsA(isA<AnEventThisDeviceDidNotAskFor>()));
    await expectLater(keri.rotateAid(name: core.aid),
        throwsA(isA<AnEventThisDeviceDidNotAskFor>()));
    expect(core.posted, isNot(contains('/api/cesr/encode')));
    expect(core.posted, isNot(contains('/api/events/prepare')),
        reason: 'nothing is built on an event this device did not ask for');
  });

  test('an interaction the core added on its own is never signed', () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    core.add({
      't': 'ixn',
      'a': [
        {'d': 'Esomething the core wants anchored'}
      ]
    });
    core.posted.clear();
    await expectLater(keri.signPayload(name: core.aid, data: [1]),
        throwsA(isA<AnEventThisDeviceDidNotAskFor>()));
    expect(core.posted, isNot(contains('/api/cesr/encode')));
  });

  test('a rotation that commits to any key but the next one is not signed',
      () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    core.foreignNext = strangersKey(0);
    core.posted.clear();
    await expectLater(
        keri.rotateAid(name: core.aid),
        throwsA(isA<NotTheEventExpected>()
            .having((e) => e.difference, 'difference', contains('"n"'))));
    await nothingSigned(core);
    // Nor is it signed later: the core never added it, and the next rotation
    // is prepared again and checked again.
    expect(core.kel, hasLength(1));
    await expectLater(
        keri.rotateAid(name: core.aid), throwsA(isA<NotTheEventExpected>()));
    await nothingSigned(core);
    core.foreignNext = null;
    await keri.rotateAid(name: core.aid);
    expect((core.kel.last['n'] as List).first, await km.nextKeyDigest(key(2)));
  });

  test(
      'an interaction left unsigned before a rotation is signed with the key in force at it',
      () async {
    foundedByAnEarlierVersion(core);
    await strandedByAnEarlierVersion(
        core, {'t': 'ixn', 'a': []}, {'anchors': []});
    final ixn = core.kel.length - 1;
    // A rotation added and signed since, by this device on another occasion.
    core.add(FakeCore.rotation(key(1), key(2)), signedBy: signer(1));
    await keri.signPayload(name: core.aid, data: [1]);
    expect(core.kel[ixn]['sig'], isNotNull);
    expect(verifiesUnder(key(0), core.raw(ixn), core.sigAt(ixn)), isTrue,
        reason:
            'the interaction came before the rotation, so the founding key signs it, not the key in force now');
  });

  test('a founding that commits to somebody else\'s next key is never signed',
      () async {
    core.foreignNext = strangersKey(0);
    await expectLater(keri.inceptAid(name: 'me', code: words.join(' ')),
        throwsA(isA<NotTheEventExpected>()));
    await nothingSigned(core,
        reason: 'a founding refused here is nothing to finish later');
    expect(core.kel, isEmpty);
  });

  test(
      'a rotation that changes anything this device did not ask for is not signed',
      () async {
    const witness = 'BKRaC6UsijUY1FRjExoAMc8WOHBDIfIKYnOlxWH8eOe8';
    final cases = <String, Map<String, dynamic> Function(Map<String, dynamic>)>{
      'a witness removed': (r) => {
            ...r,
            'br': [witness]
          },
      'a witness added': (r) => {
            ...r,
            'ba': [witness]
          },
      'the witness threshold': (r) => {...r, 'bt': '1'},
      'the signing threshold': (r) => {...r, 'kt': '2'},
      'the next threshold': (r) => {...r, 'nt': '2'},
      'an anchor': (r) => {
            ...r,
            'a': [
              {'d': 'Esomething'}
            ]
          },
      'the post-quantum commitment': (r) => {
            ...r,
            'n': [(r['n'] as List).first, 'E${'Q' * 43}']
          },
    };
    for (final MapEntry(key: what, value: change) in cases.entries) {
      await freshDevice();
      core = FakeCore();
      keri = serviceOver(core);
      await keri.inceptAid(name: 'me', code: words.join(' '));
      core.changeRotation = change;
      core.posted.clear();
      await expectLater(
          keri.rotateAid(name: core.aid), throwsA(isA<NotTheEventExpected>()),
          reason: what);
      await nothingSigned(core,
          reason: 'a rotation with $what changed was signed');
    }
  });

  test('an interaction anchoring anything but what was asked is not signed',
      () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    core.interactionAnchors = [
      {'d': 'Esomething else'}
    ];
    core.posted.clear();
    await expectLater(
        keri.interactAid(name: core.aid, sealData: [
          {'d': 'Ewhat was asked'}
        ]),
        throwsA(isA<NotTheEventExpected>()));
    await nothingSigned(core);
    expect(core.kel, hasLength(1));
  });

  test('a credential anchor that is not the credential issued is not signed',
      () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    core.credentialAnchor = [
      {'i': 'Esomething else', 's': '0', 'd': 'Esomething else'}
    ];
    core.posted.clear();
    await expectLater(keri.issueCredential(claims: {'a': 'b'}, schemaSaid: 'E'),
        throwsException);
    expect(core.posted, isNot(contains('/api/cesr/encode')));
    expect(await pending(), isEmpty);
  });

  // Replaces "a request refused or answered wrongly is forgotten, one lost in
  // transit is kept": what is kept now is the reservation of an event this
  // device signed, not a note of what it asked the core to add.
  test(
      'an event refused or answered wrongly leaves no reservation, one signed and lost in transit is kept and committed later',
      () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    core.refusesToPrepare = true;
    await expectLater(keri.rotateAid(name: core.aid), throwsException);
    expect(await reservations(core.aid), isEmpty, reason: 'refused');
    core.refusesToPrepare = false;
    core.foreignNext = strangersKey(0);
    await expectLater(keri.rotateAid(name: core.aid), throwsException);
    expect(await reservations(core.aid), isEmpty,
        reason: 'answered with something that is not the rotation');
    core.foreignNext = null;

    // The commit never reaches the core: it has nothing, and this device has
    // the signed event.
    core.dropsRequestsTo = '/api/events/commit';
    await expectLater(
        keri.interactAid(name: core.aid), throwsA(isA<http.ClientException>()));
    expect(core.kel, hasLength(1));
    final kept = await reservations(core.aid);
    expect(kept, hasLength(1), reason: 'lost in transit: signed and kept');
    expect(kept.single.sn, 1);
    expect(kept.single.signed, isTrue);

    // The next event commits it first, with the same digest.
    core.dropsRequestsTo = null;
    await keri.interactAid(name: core.aid, sealData: [
      {'d': 'Esecond'}
    ]);
    expect(core.kel.map((e) => e['t']), ['icp', 'ixn', 'ixn']);
    expect(core.kel[1]['d'], kept.single.digest);
    expect(await reservations(core.aid), isEmpty);
  });

  test('a stranded event, once finished, is no longer written down', () async {
    foundedByAnEarlierVersion(core);
    await strandedByAnEarlierVersion(core, FakeCore.rotation(key(1), key(2)),
        {'key': key(1), 'next': key(2)});
    expect(await pending(), hasLength(1),
        reason: 'the stranded rotation is written down');
    await keri.signPayload(name: core.aid, data: [1]);
    expect(await pending(), isEmpty);
  });

  test(
      'a request whose answer never arrived is recognised only at its own sequence number',
      () async {
    foundedByAnEarlierVersion(core);
    final asked = TheEventsThisDeviceAskedFor();
    // Asked for at sequence 1, the answer lost; the core holds the rotation at 2.
    await asked.asking(
        t: 'rot',
        aid: core.aid,
        expectedSn: 1,
        asked: {'key': key(1), 'next': key(2)});
    core.add({'t': 'ixn', 'a': []}, signedBy: signer(0));
    core.add(FakeCore.rotation(key(1), key(2)));
    core.posted.clear();
    await expectLater(keri.signPayload(name: core.aid, data: [1]),
        throwsA(isA<AnEventThisDeviceDidNotAskFor>()));
    expect(core.posted, isNot(contains('/api/cesr/encode')));
    // And it is dropped once a signed event holds its place.
    core.removeLast();
    await keri.signPayload(name: core.aid, data: [1]);
    expect(await pending(), isEmpty,
        reason: 'sequence 1 is now held by a signed event');
  });

  test(
      'a request whose answer never arrived is recognised by its keys, at its sequence number',
      () async {
    foundedByAnEarlierVersion(core);
    final asked = TheEventsThisDeviceAskedFor();
    await asked.asking(
        t: 'rot',
        aid: core.aid,
        expectedSn: 1,
        asked: {'key': key(1), 'next': key(2)});
    // The rotation at 1 reveals the key asked for but commits to another.
    core.add(FakeCore.rotation(key(1), strangersKey(0)));
    core.posted.clear();
    await expectLater(keri.signPayload(name: core.aid, data: [1]),
        throwsA(isA<AnEventThisDeviceDidNotAskFor>()));
    expect(core.posted, isNot(contains('/api/cesr/encode')));
    // The rotation it did ask for is finished.
    core.removeLast();
    core.add(FakeCore.rotation(key(1), key(2)));
    await keri.signPayload(name: core.aid, data: [1]);
    expect(core.kel.last['sig'], isNotNull);
  });

  // The prepare-and-commit counterpart of the two above: an event signed and
  // never acknowledged is recognised by its digest, at its place, and nothing
  // else is signed there.
  test(
      'a place reserved for an event is held against any other, and released by committing that event',
      () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    const asked = [
      {'d': 'Easked'}
    ];
    // Reserved, and the signature never made it out: the place is held.
    core.dropsRequestsTo = '/api/cesr/encode';
    await expectLater(keri.interactAid(name: core.aid, sealData: asked),
        throwsA(isA<http.ClientException>()));
    core.dropsRequestsTo = null;
    final held = await reservations(core.aid);
    expect(held, hasLength(1));
    expect(held.single.signed, isFalse);

    core.posted.clear();
    await expectLater(
        keri.interactAid(name: core.aid, sealData: [
          {'d': 'Esomethingelse'}
        ]),
        throwsA(isA<PlaceAlreadyReserved>()));
    expect(core.posted, isNot(contains('/api/cesr/encode')),
        reason: 'a second event is never signed at a reserved place');
    expect(core.kel, hasLength(1));

    // The event it was reserved for is signed and committed there.
    await keri.interactAid(name: core.aid, sealData: asked);
    expect(core.kel[1]['d'], held.single.digest);
    expect(core.kel[1]['a'], asked);
    expect(await reservations(core.aid), isEmpty);
  });

  test('requests written down at the same moment are all kept', () async {
    final asked = TheEventsThisDeviceAskedFor();
    await Future.wait([
      for (var i = 0; i < 20; i++)
        asked.asking(t: 'ixn', aid: 'Eaid', expectedSn: i)
    ]);
    expect(await pending(), hasLength(20),
        reason: 'each write read the list another was writing');
  });

  test(
      'an event this device did not ask for is signed only once the person approves it',
      () async {
    foundedByAnEarlierVersion(core);
    core.add({
      't': 'ixn',
      'a': [
        {'d': 'Emade on another of their devices'}
      ]
    });
    final ixn = core.kel.last;
    final keys = TheKeyInForce(core.client(), 'http://core.test');
    final awaiting = await keys.eventsAwaitingApproval(seed);
    expect(awaiting.map((e) => e['d']), [ixn['d']]);
    await expectLater(keri.signPayload(name: core.aid, data: [1]),
        throwsA(isA<AnEventThisDeviceDidNotAskFor>()),
        reason: 'the identity is locked until somebody acts');
    await keys.signApprovedEvent(seed,
        sequenceNumber: ixn['s'] as String, digest: ixn['d'] as String);
    expect(core.kel.last['sig'], isNotNull);
    await keri.signPayload(name: core.aid, data: [1]);

    // Approval does not lift the rotation checks.
    core.add(FakeCore.rotation(key(1), strangersKey(0)));
    core.posted.clear();
    await expectLater(
        keys.signApprovedEvent(seed,
            sequenceNumber: core.kel.last['s'] as String,
            digest: core.kel.last['d'] as String),
        throwsA(predicate((e) => '$e'.contains('not to the next key'))));
    expect(core.posted, isNot(contains('/api/cesr/encode')));
  });

  // Was one test of a founding the core built: it added these only where it
  // was given the phrase. Now the app asks for both itself, so a core adding
  // either to what it prepares is refused whatever it was given; a founding
  // an earlier version left unsigned is still finished only where it was.
  test(
      'a post-quantum commitment or messaging keys the core adds of its own to a founding it prepares are never signed',
      () async {
    for (final given in [false, true]) {
      await freshDevice();
      core = FakeCore()..addsItsOwn = true;
      keri = serviceOver(core, theCoreWasGivenThisPhrase: given);
      await expectLater(keri.inceptAid(name: 'me', code: words.join(' ')),
          throwsA(isA<NotTheEventExpected>()),
          reason: 'given the phrase: $given');
      await nothingSigned(core, reason: 'given the phrase: $given');
      expect(core.kel, isEmpty);
    }
  });

  test(
      'a stranded founding carrying the core\'s own post-quantum commitment and messaging keys is finished only where it was given the phrase',
      () async {
    Future<void> strandedFounding(FakeCore c) => strandedByAnEarlierVersion(
        c,
        FakeCore.oldFounding(key(0), key(1),
            n: ['E${'P' * 43}'], a: [FakeCore.keysetAnchor]),
        {'key': key(0), 'next': key(1)});

    await strandedFounding(core);
    core.posted.clear();
    await expectLater(keri.signPayload(name: core.aid, data: [1]),
        throwsA(predicate((e) => '$e'.contains('was not given this phrase'))),
        reason: 'the app did not hand this core its phrase');
    expect(core.posted, isNot(contains('/api/cesr/encode')));

    await freshDevice();
    core = FakeCore();
    keri = serviceOver(core, theCoreWasGivenThisPhrase: true);
    await strandedFounding(core);
    await keri.signPayload(name: core.aid, data: [1]);
    expect(core.kel.first['sig'], isNotNull,
        reason: 'the app handed this core its phrase');
    expect(verifiesUnder(key(0), core.raw(0), core.sigAt(0)), isTrue);
  });

  test(
      'a founding that differs from the one asked for in anything else is never signed',
      () async {
    final stranger = strangersKey(0);
    final cases = <String, Map<String, dynamic> Function(Map<String, dynamic>)>{
      'a third commitment': (f) => {
            ...f,
            'n': [...f['n'] as List, 'E${'T' * 43}']
          },
      'a first commitment to another key': (f) => {
            ...f,
            'n': [
              TheKeyInForce.commitmentTo(stranger),
              ...(f['n'] as List).skip(1)
            ]
          },
      'another post-quantum commitment': (f) => {
            ...f,
            'n': [(f['n'] as List).first, 'E${'Q' * 43}']
          },
      'another key': (f) => {
            ...f,
            'k': [stranger]
          },
      'a signing threshold of two': (f) => {...f, 'kt': '2'},
      'a next threshold of two': (f) => {...f, 'nt': '2'},
      'a configuration trait': (f) => {
            ...f,
            'c': ['EO']
          },
      'a witness nobody asked for': (f) => {
            ...f,
            'b': ['BKRaC6UsijUY1FRjExoAMc8WOHBDIfIKYnOlxWH8eOe8'],
            'bt': '1'
          },
      'a second anchor': (f) => {
            ...f,
            'a': [
              ...f['a'] as List,
              {'d': 'Esomething'}
            ]
          },
      'an anchor that is not a keyset': (f) => {
            ...f,
            'a': [
              {'d': 'Esomething'}
            ]
          },
      'a keyset with something more': (f) => {
            ...f,
            'a': [
              {...(f['a'] as List).first as Map, 'x': 1}
            ]
          },
      'no messaging keys': (f) => {...f, 'a': []},
    };
    for (final MapEntry(key: what, value: change) in cases.entries) {
      await freshDevice();
      core = FakeCore()..changeFounding = change;
      // Even a core given the phrase may not change the founding.
      keri = serviceOver(core, theCoreWasGivenThisPhrase: true);
      await expectLater(keri.inceptAid(name: 'me', code: words.join(' ')),
          throwsA(isA<NotTheEventExpected>()),
          reason: what);
      await nothingSigned(core, reason: 'a founding with $what was signed');
      expect(core.kel, isEmpty, reason: what);
    }
  });

  // Replaces "a rotation whose answer was lost after the core added it is
  // finished later, without approval": the core adds an event only once it is
  // signed, so what a lost answer leaves is a reservation, committed again.
  test(
      'a rotation whose commit answer was lost is committed again with the same digest, one event at its place',
      () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    core.dropsAnswersFrom = '/api/events/commit';
    await expectLater(
        keri.rotateAid(name: core.aid), throwsA(isA<http.ClientException>()));
    expect(core.kel.map((e) => e['t']), ['icp', 'rot'],
        reason: 'the core recorded it; only its answer was lost');
    expect(core.kel.last['sig'], isNotNull);
    final left = await reservations(core.aid);
    expect(left, hasLength(1));
    expect(left.single.digest, core.kel[1]['d']);

    core.dropsAnswersFrom = null;
    core.posted.clear();
    await keri.interactAid(name: core.aid);
    expect(core.posted.where((p) => p == '/api/events/commit'), hasLength(2),
        reason: 'the rotation is committed again before the interaction');
    expect(core.kel.map((e) => e['t']), ['icp', 'rot', 'ixn']);
    expect(core.kel[1]['d'], left.single.digest);
    expect(core.kel[2]['p'], left.single.digest);
    expect(await reservations(core.aid), isEmpty);
    expect(await pending(), isEmpty);
  });

  test('a founding that is not a founding at sequence zero is never signed',
      () async {
    final cases = <String, void Function(FakeCore)>{
      'a delegated founding': (c) =>
          c.changeFounding = (f) => {...f, 't': 'dip'},
      'a digest that is not its own': (c) => c.misdigests = true,
      'numbered one past zero': (c) => c.skipsASequenceNumber = true,
    };
    for (final MapEntry(key: what, value: tamper) in cases.entries) {
      await freshDevice();
      core = FakeCore();
      tamper(core);
      keri = serviceOver(core);
      await expectLater(keri.inceptAid(name: 'me', code: words.join(' ')),
          throwsA(isA<NotTheEventExpected>()),
          reason: what);
      await nothingSigned(core, reason: what);
      expect(core.kel, isEmpty, reason: what);
    }
  });

  test(
      'a stranded founding committing to one more key than this core may add is not finished',
      () async {
    // An earlier version asked for this founding, and the answer never arrived.
    await TheEventsThisDeviceAskedFor().asking(
        t: 'icp', expectedSn: 0, asked: {'key': key(0), 'next': key(1)});
    core.add(FakeCore.oldFounding(key(0), key(1), n: ['E${'M' * 43}']));
    core.posted.clear();
    await expectLater(keri.signPayload(name: core.aid, data: [1]),
        throwsA(predicate((e) => '$e'.contains('was not given'))));
    expect(core.posted, isNot(contains('/api/cesr/encode')));
  });

  test('a rotation or interaction the core numbers wrongly is not signed',
      () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    core.skipsASequenceNumber = true;
    core.posted.clear();
    await expectLater(
        keri.rotateAid(name: core.aid), throwsA(isA<NotTheEventExpected>()));
    await nothingSigned(core);
    await expectLater(
        keri.interactAid(name: core.aid), throwsA(isA<NotTheEventExpected>()));
    await nothingSigned(core);
    expect(core.kel, hasLength(1));
  });

  test(
      'a credential anchor of another identity, or numbered wrongly, is not signed',
      () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    core.anchorsAs = 'E${'O' * 43}';
    core.posted.clear();
    await expectLater(keri.issueCredential(claims: {'a': 'b'}, schemaSaid: 'E'),
        throwsException);
    expect(core.posted, isNot(contains('/api/cesr/encode')));
    core.removeLast();
    core.anchorsAs = null;
    core.skipsASequenceNumber = true;
    await expectLater(keri.issueCredential(claims: {'a': 'b'}, schemaSaid: 'E'),
        throwsException);
    expect(core.posted, isNot(contains('/api/cesr/encode')));
  });

  test(
      'an interaction whose answer never arrived is recognised only by the anchors asked for',
      () async {
    foundedByAnEarlierVersion(core);
    await TheEventsThisDeviceAskedFor()
        .asking(t: 'ixn', aid: core.aid, expectedSn: 1, asked: {
      'anchors': [
        {'d': 'Easked'}
      ]
    });
    core.add({
      't': 'ixn',
      'a': [
        {'d': 'Esomethingelse'}
      ]
    });
    core.posted.clear();
    await expectLater(keri.signPayload(name: core.aid, data: [1]),
        throwsA(isA<AnEventThisDeviceDidNotAskFor>()));
    expect(core.posted, isNot(contains('/api/cesr/encode')));
    core.removeLast();
    core.add({
      't': 'ixn',
      'a': [
        {'d': 'Easked'}
      ]
    });
    await keri.signPayload(name: core.aid, data: [1]);
    expect(core.kel.last['sig'], isNotNull);
  });

  test('a request is forgotten once the core has signed its event itself',
      () async {
    await keri.inceptAid(name: 'me', code: words.join(' '));
    await keri.issueCredential(claims: {'a': 'b'}, schemaSaid: 'E');
    expect(await pending(), hasLength(1),
        reason: 'the anchor is written down until it is signed');
    core.kel.last['sig'] = 'signed by the core';
    await keri.signPayload(name: core.aid, data: [1]);
    expect(await pending(), isEmpty);
  });

  test(
      'approval signs only an interaction, founding or rotation still waiting for its signature',
      () async {
    foundedByAnEarlierVersion(core);
    final keys = TheKeyInForce(core.client(), 'http://core.test');
    // Already signed.
    await expectLater(
        keys.signApprovedEvent(seed, sequenceNumber: '0', digest: core.aid),
        throwsA(predicate((e) => '$e'.contains('not waiting'))));
    for (final t in ['dip', 'drt']) {
      core.add({...FakeCore.rotation(key(1), key(2)), 't': t});
      core.posted.clear();
      await expectLater(
          keys.signApprovedEvent(seed,
              sequenceNumber: core.kel.last['s'] as String,
              digest: core.kel.last['d'] as String),
          throwsException,
          reason: t);
      expect(core.posted, isNot(contains('/api/cesr/encode')), reason: t);
      core.removeLast();
    }
  });

  // Replaces "a founding whose answer was lost after the core added it is
  // finished later, without approval".
  test(
      'a founding whose commit answer was lost is committed again with the same digest',
      () async {
    core.dropsAnswersFrom = '/api/events/commit';
    await expectLater(keri.inceptAid(name: 'me', code: words.join(' ')),
        throwsA(isA<http.ClientException>()));
    expect(core.kel.single['t'], 'icp');
    expect(core.kel.single['sig'], isNotNull,
        reason: 'the core recorded it; only its answer was lost');
    final left = await reservations(core.aid);
    expect(left.single.digest, core.aid);

    core.dropsAnswersFrom = null;
    await keri.interactAid(name: core.aid);
    expect(core.kel.map((e) => e['t']), ['icp', 'ixn']);
    expect(core.kel.first['d'], left.single.digest);
    expect(await reservations(core.aid), isEmpty);
  });

  test(
      'a founding whose commit never reached the core is committed with the same digest when founding is tried again',
      () async {
    core.dropsRequestsTo = '/api/events/commit';
    await expectLater(keri.inceptAid(name: 'me', code: words.join(' ')),
        throwsA(isA<http.ClientException>()));
    expect(core.kel, isEmpty);
    final aid = eventIn(core.prepared.single)['i'] as String;
    final left = await reservations(aid);
    expect(left.single.signed, isTrue);

    core.dropsRequestsTo = null;
    final founded = await keri.inceptAid(name: 'me', code: words.join(' '));
    expect(founded.aid, aid);
    expect(core.kel.single['d'], left.single.digest,
        reason: 'the same founding, not a second identity');
    expect(await reservations(aid), isEmpty);
  });
}
