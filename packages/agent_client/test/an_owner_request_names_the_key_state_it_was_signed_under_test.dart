import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/crypto/owner_signature.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/owner_signing_client.dart';
import 'package:agent_client/services/the_events_this_device_signed.dart';
import 'package:agent_client/services/the_identity_this_device_holds.dart';
import 'package:agent_client/services/the_key_events_this_device_makes.dart';
import 'package:agent_client/services/the_key_state_this_device_reads.dart';
import 'package:agent_client/services/the_witnesses_of_this_devices_events.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

import 'support/a_core_that_misleads.dart';
import 'support/a_witness.dart';
import 'support/the_core.dart';

/// An Identity Agent an owner reaches over the network, applying the core's
/// rule for a stale owner signature (`ownerKeyStateIsStale`) to the owner's
/// log as the identity's core serves it, verified: a request signed by the
/// key in force, naming it, is served; one signed by an earlier key, naming
/// the establishment event that put that key in force, is told the key state
/// is stale; anything else is refused.
class _AnAgentOwnedByTheIdentity {
  _AnAgentOwnedByTheIdentity._(this._server, this._km, this._logAt, this._aid);

  static Future<_AnAgentOwnedByTheIdentity> start(
      KeyMath km, String coreBase, String aid) async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final a = _AnAgentOwnedByTheIdentity._(server, km, coreBase, aid);
    server.listen(a._answer);
    return a;
  }

  final HttpServer _server;
  final KeyMath _km;
  final String _logAt;
  final String _aid;
  String get origin => 'http://127.0.0.1:${_server.port}';

  /// Each request: the key state it named, the key that signed it, and the
  /// answer.
  final seen = <(String, String, int)>[];

  Future<void> close() => _server.close(force: true);

  Future<void> _answer(HttpRequest req) async {
    final body = await req.fold<List<int>>([], (a, b) => a..addAll(b));
    final res = await http.get(Uri.parse('$_logAt/public/oobi/$_aid'));
    final j = jsonDecode(res.body) as Map<String, dynamic>;
    final raws = j['raw_events_b64'] as List;
    final sigs = j['cesr_signatures'] as List;
    final st = await _km.verifyLog(_aid, [
      for (var i = 0; i < raws.length; i++)
        SignedCopy('${raws[i]}', ['${sigs[i]}'])
    ]);
    final est = [
      for (final e in st.events)
        if (e.establishment) e
    ];
    final named = req.headers.value(OwnerSigningClient.keyStateHeader) ?? '';
    final message = OwnerSignature.canonicalStringOver(
        method: req.method,
        path: req.uri.path,
        timestamp: req.headers.value(OwnerSignature.timestampHeader) ?? '',
        bodyDigest: OwnerSignature.blake3QB64(body));
    final sig = _raw(req.headers.value(OwnerSignature.sigHeader) ?? '', '0B');
    String? signer;
    for (final e in est) {
      if (sig != null &&
          ed.verify(ed.PublicKey(_raw(e.keys.first, 'D')!),
              utf8.encode(message), sig)) {
        signer = e.keys.first;
      }
    }
    final last = est.last;
    final placeOf = {
      for (final e in est) '${e.sn.toRadixString(16)}.${e.digest}': e
    };
    int status;
    if (signer == null || !placeOf.containsKey(named)) {
      status = 403;
    } else if (named == '${last.sn.toRadixString(16)}.${last.digest}') {
      status = signer == last.keys.first ? 200 : 403;
    } else {
      status = signer == placeOf[named]!.keys.first ? 401 : 403;
    }
    seen.add((named, signer ?? '', status));
    req.response.statusCode = status;
    req.response.headers.contentType = ContentType.json;
    req.response.write(jsonEncode(
        status == 401 ? {'error': 'stale_key_state'} : {'ok': status == 200}));
    await req.response.close();
  }

  static Uint8List? _raw(String qb64, String code) {
    if (!qb64.startsWith(code)) return null;
    final b =
        base64Url.decode('${'A' * code.length}${qb64.substring(code.length)}');
    return Uint8List.fromList(b.sublist(code.length));
  }
}

void main() {
  late String bin;
  late KeyMath km;
  late AWitness w1, w2, w3;
  late ACore core;
  late TheWitnessesOfThisDevicesEvents witnesses;
  const phrase =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  final seed = Bip39.mnemonicToSeed(phrase.split(' '));

  setUpAll(() async {
    bin = await buildTheCore('owner-key-state-core', dev: true);
    km = await keyMathOf(bin);
    w1 = await AWitness.start(km);
    w2 = await AWitness.start(km);
    w3 = await AWitness.start(km);
    witnesses = TheWitnessesOfThisDevicesEvents(
        http.Client(),
        km,
        KnownWitnesses({
          for (final w in [w1, w2, w3]) w.aid: w.base
        }));
  });

  tearDownAll(() async {
    for (final w in [w1, w2, w3]) {
      await w.close();
    }
  });

  setUp(() async {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
    for (final w in [w1, w2, w3]) {
      w.forgetAll();
    }
    core = await anotherCore(bin, km);
  });

  tearDown(() => core.close());

  test(
      'a rotation whose commit answer was lost is learned from the witnesses '
      'when the agent says the key state is stale, and the request goes again '
      'under the new key, never a key it named wrongly', () async {
    final makes = TheKeyEventsThisDeviceMakes(core.client, core.base, km,
        witnesses: witnesses, held: TheIdentityThisDeviceHolds());
    final founded =
        await makes.found(seed, witnesses: [w1.aid, w2.aid, w3.aid], toad: 2);
    final set = WitnessSet([w1.aid, w2.aid, w3.aid], 2);

    // The rotation reaches the core, and its answer is lost: the device's
    // record still says the founding key is in force. The event went to the
    // witnesses meanwhile.
    core.client.loseTheNextCommitsAnswer = true;
    await expectLater(
        makes.rotate(seed,
            aid: founded.aid,
            generation: 0,
            afterSn: 0,
            afterDigest: founded.digest,
            toad: 2,
            witnessedBy: set),
        throwsA(isA<http.ClientException>()));
    expect((await TheIdentityThisDeviceHolds().read())!.generation, 0);

    final agent =
        await _AnAgentOwnedByTheIdentity.start(km, core.base, founded.aid);
    addTearDown(agent.close);
    final reader = TheKeyStateThisDeviceReads(core.client, km, core.base);
    final owner = ownerKeyFromThePhrase(() async => phrase.split(' '),
        (String m) => Bip39.mnemonicToSeed(m.split(" ")), reader);
    final client = OwnerSigningClient(
        agentOrigin: agent.origin,
        ownerKey: owner.ownerKey,
        onStaleKeyState: owner.onStaleKeyState,
        inner: http.Client());

    final res = await client.get(Uri.parse('${agent.origin}/api/identity'));
    expect(res.statusCode, 200, reason: '${agent.seen}');

    final key0 = KeyManager.keyAt(seed, 0).publicKeyEncoded;
    final key1 = KeyManager.keyAt(seed, 1).publicKeyEncoded;
    final rotation = await TheEventsThisDeviceSigned().unfinished(founded.aid);
    expect(agent.seen, [
      ('0.${founded.digest}', key0, 401),
      ('1.${rotation.single.digest}', key1, 200),
    ]);

    // The lost answer is finished too: the core has the rotation already.
    final finished = await makes.finishSigned(founded.aid, witnessedBy: set);
    expect(finished.single.status, 'already_recorded');
    expect(await TheEventsThisDeviceSigned().unfinished(founded.aid), isEmpty);
  });

  test(
      'a stale answer is handed back as it came where the client was given no '
      'way to read the key again, and nothing is sent twice', () async {
    final makes = TheKeyEventsThisDeviceMakes(core.client, core.base, km,
        witnesses: witnesses, held: TheIdentityThisDeviceHolds());
    final founded =
        await makes.found(seed, witnesses: [w1.aid, w2.aid, w3.aid], toad: 2);
    core.client.loseTheNextCommitsAnswer = true;
    await expectLater(
        makes.rotate(seed,
            aid: founded.aid,
            generation: 0,
            afterSn: 0,
            afterDigest: founded.digest,
            toad: 2,
            witnessedBy: WitnessSet([w1.aid, w2.aid, w3.aid], 2)),
        throwsA(isA<http.ClientException>()));
    final agent =
        await _AnAgentOwnedByTheIdentity.start(km, core.base, founded.aid);
    addTearDown(agent.close);
    final owner = ownerKeyFromThePhrase(
        () async => phrase.split(' '),
        (String m) => Bip39.mnemonicToSeed(m.split(" ")),
        TheKeyStateThisDeviceReads(core.client, km, core.base));
    final client = OwnerSigningClient(
        agentOrigin: agent.origin,
        ownerKey: owner.ownerKey,
        inner: http.Client());
    final res = await client.get(Uri.parse('${agent.origin}/api/identity'));
    expect(res.statusCode, 401);
    expect(jsonDecode(res.body)['error'], 'stale_key_state');
    expect(agent.seen, hasLength(1));
  });
}
