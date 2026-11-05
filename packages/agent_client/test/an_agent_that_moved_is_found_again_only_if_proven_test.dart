import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/config/agent_config.dart';
import 'package:agent_client/crypto/endpoint_record.dart';
import 'package:agent_client/services/finding_an_agent_that_moved.dart';
import 'package:agent_client/services/the_newest_signed_address.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:agent_client/services/point_this_app_at_its_agent.dart';
import 'package:agent_client/services/which_half_this_app_is_running.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

/// An organisation that changed address is found again, but only at an address
/// proven to be the same organisation.
///
/// The case that started this: the app was recorded against a temporary
/// address; the organisation then moved to a stable one. The old address was dead,
/// the app pushed it to its core at every launch, and opening the organisation
/// failed with an error that named no cause.
const _aid = 'EORGANISATION';
const _old = 'https://old-tunnel.example.test';
const _new = 'https://box.example.test';
const _impostor = 'https://impostor.example.test';
const _witness = 'https://witness.example.test';

// --- signing, the way the Go package does it (ADR-062) ----------------------
String _b64(List<int> b) => base64Url.encode(b).replaceAll('=', '');
String _qb64Key(ed.PublicKey k) => 'D${_b64([0, ...k.bytes]).substring(1)}';
String _qb64Sig(List<int> sig) => '0B${_b64([0, 0, ...sig]).substring(2)}';

final _orgKey = ed.generateKey();
final _rotatedOutKey = ed.generateKey();

Map<String, dynamic> _record(String origin, String issued,
    {String aid = _aid, ed.KeyPair? signer}) {
  final r = <String, dynamic>{
    'type': 'endpoint-record/1',
    'aid': aid,
    'origin': origin,
    'issued': issued,
  };
  final bytes = endpointRecordSignedBytes(r)!;
  final sig = ed.sign(
      (signer ?? _orgKey).privateKey, Uint8List.fromList(utf8.encode(bytes)));
  return {...r, 'signature': _qb64Sig(sig)};
}

String _originOf(String address) => canonicalOriginOf(address)!;

/// A small world: which hosts are alive, which identifier each one's published
/// key history proves, and which of them recognise this computer.
class _World {
  final alive = <String>{};
  final keyHistoryProves = <String, String>{};
  final recognisesUs = <String, String>{}; // host -> identifier it answers with
  final seen = <http.Request>[];

  /// What the witness serves for the organisation.
  final witnessHolds = <Map<String, dynamic>>[];

  /// Witness addresses the verified key log names, as the core reports them.
  final logWitnesses = <String>[];

  /// Witness addresses the core holds for the organisation's stored log.
  final coreHoldsWitnesses = <String>[];

  /// A witness that answers with a record signed by the wrong key.
  String? hostileWitness;

  /// Hosts that are up but answer with something that is not an agent.
  final notAnAgent = <String>{};

  /// Hosts a relay answers for with 502, because the machine behind is off.
  final machineOff = <String>{};
  int statusForMachineOff = 502;

  /// When set, a request to a dead host waits for this before failing, as an
  /// address that does not answer really does.
  Completer<void>? holdDeadHosts;

  http.Client client() => MockClient((req) async {
        seen.add(req);
        final host = '${req.url.scheme}://${req.url.host}';
        if (req.url.host == '127.0.0.1') {
          if (req.url.path == '/api/controller/sign') {
            return http.Response(
                '{"controller_aid":"B","signature":"0B","timestamp":"t"}', 200);
          }
          if (req.url.path == '/api/verify/identity-elsewhere') {
            final body = jsonDecode(req.body) as Map<String, dynamic>;
            final oobi = Uri.parse(body['oobi_url'] as String);
            final proves = keyHistoryProves['${oobi.scheme}://${oobi.host}'];
            if (proves == null || proves != body['aid']) {
              return http.Response(
                  jsonEncode({
                    'verified': false,
                    'why': 'that history names '
                        '${proves ?? 'nobody'}'
                  }),
                  200);
            }
            return http.Response(
                jsonEncode({
                  'verified': true,
                  'aid': proves,
                  'public_key': _qb64Key(_orgKey.publicKey),
                  'witnesses': [
                    for (final u in logWitnesses) {'key': 'BKEY', 'url': u}
                  ],
                }),
                200);
          }
          if (req.url.path == '/api/contacts/$_aid/witnesses') {
            return coreHoldsWitnesses.isEmpty
                ? http.Response('{}', 404)
                : http.Response(
                    jsonEncode({
                      'witnesses': [
                        for (final u in coreHoldsWitnesses)
                          {'key': 'BKEY', 'url': u}
                      ]
                    }),
                    200);
          }
          return http.Response('{}', 200); // front-end-for etc.
        }
        if (host == hostileWitness && req.url.path == '/api/witness/endpoint/$_aid') {
          return http.Response(
              jsonEncode({
                'record': _record(_originOf(_impostor), '2026-11-02T10:00:00Z',
                    signer: _rotatedOutKey)
              }),
              200);
        }
        if (host == _witness && req.url.path == '/api/witness/endpoint/$_aid') {
          if (witnessHolds.isEmpty) return http.Response('{}', 404);
          return http.Response(jsonEncode({'record': witnessHolds.last}), 200);
        }
        if (notAnAgent.contains(host)) return http.Response('not here', 404);
        if (machineOff.contains(host))
          return http.Response('bad gateway', statusForMachineOff);
        if (!alive.contains(host)) {
          await holdDeadHosts?.future;
          throw http.ClientException('no route', req.url);
        }
        if (req.url.path == '/api/health') {
          return http.Response('{"status":"active","agent":"keri-go"}', 200);
        }
        if (req.url.path == '/api/controller/agent') {
          final aid = recognisesUs[host];
          return aid == null
              ? http.Response('no', 403)
              : http.Response(jsonEncode({'aid': aid}), 200);
        }
        return http.Response('{}', 404);
      });
}

void main() {
  late _World world;
  late FindingAnAgentThatMoved finder;

  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    world = _World()
      ..witnessHolds.add(_record(_originOf(_new), '2026-11-01T10:00:00Z'));
    await rememberWitnessesOf(_aid, [_witness]);
    await WhichHalfThisAppIsRunning.pointAt(agentOrigin: _old, agentAid: _aid);
    finder = FindingAnAgentThatMoved(client: world.client());
  });
  tearDown(() {
    AgentConfig.agentOrigin = '';
    AgentConfig.agentAid = '';
  });

  Future<WhichHalfThisAppIsRunning> recorded() =>
      WhichHalfThisAppIsRunning.now();

  group('where the witnesses are learned', () {
    void aMovedOrgAtNew() => world
      ..alive.add(_new)
      ..keyHistoryProves[_new] = _aid
      ..recognisesUs[_new] = _aid;

    test('from the witnesses the organisation\'s own key log names', () async {
      SharedPreferences.setMockInitialValues({}); // nothing remembered
      await WhichHalfThisAppIsRunning.pointAt(
          agentOrigin: _old, agentAid: _aid);
      aMovedOrgAtNew();
      world.logWitnesses.add(_witness);
      final out = await finder
          .findAgain(current: await recorded(), hints: const [_new]);
      expect(out.moved, isTrue);
    });

    test('from the addresses this computer\'s core already holds', () async {
      SharedPreferences.setMockInitialValues({});
      await WhichHalfThisAppIsRunning.pointAt(
          agentOrigin: _old, agentAid: _aid);
      aMovedOrgAtNew();
      world.coreHoldsWitnesses.add(_witness);
      final out = await finder
          .findAgain(current: await recorded(), hints: const [_new]);
      expect(out.moved, isTrue);
    });

    test('with no lead anywhere, nothing is accepted', () async {
      SharedPreferences.setMockInitialValues({});
      await WhichHalfThisAppIsRunning.pointAt(
          agentOrigin: _old, agentAid: _aid);
      aMovedOrgAtNew();
      final out = await finder
          .findAgain(current: await recorded(), hints: const [_new]);
      expect(out.moved, isFalse);
      expect((await recorded()).agentOrigin, _old);
    });

    test(
        'a witness that answers with a record the organisation did not sign '
        'is skipped, and the honest one still decides', () async {
      aMovedOrgAtNew();
      const evil = 'https://evil-witness.example.test';
      world.hostileWitness = evil;
      world.logWitnesses.add(evil);
      final out = await finder
          .findAgain(current: await recorded(), hints: const [_new]);
      expect(out.moved, isTrue);
      expect((await recorded()).agentOrigin, _new);
    });

    test('a lone hostile witness cannot move the app', () async {
      SharedPreferences.setMockInitialValues({});
      await WhichHalfThisAppIsRunning.pointAt(
          agentOrigin: _old, agentAid: _aid);
      world
        ..alive.add(_impostor)
        ..keyHistoryProves[_impostor] = _aid
        ..recognisesUs[_impostor] = _aid;
      const evil = 'https://evil-witness.example.test';
      world.hostileWitness = evil;
      world.logWitnesses.add(evil);
      final out = await finder
          .findAgain(current: await recorded(), hints: const [_impostor]);
      expect(out.moved, isFalse);
      expect((await recorded()).agentOrigin, _old);
    });
  });

  test('an agent that still answers is left exactly where it is', () async {
    world.alive.add(_old);
    final out =
        await finder.findAgain(current: await recorded(), hints: const [_new]);
    expect(out.moved, isFalse);
    expect(out.sayThis, isEmpty);
    expect((await recorded()).agentOrigin, _old);
  });

  test(
      'a dead address is replaced by a lead whose key history proves the same '
      'identifier AND which recognises this computer', () async {
    world
      ..alive.add(_new)
      ..keyHistoryProves[_new] = _aid
      ..recognisesUs[_new] = _aid;
    final out =
        await finder.findAgain(current: await recorded(), hints: const [_new]);
    expect(out.moved, isTrue);
    expect(out.sayThis, contains('has moved'));
    // Said in words: no address, no identifier.
    expect(out.sayThis, isNot(contains(_old)));
    expect(out.sayThis, isNot(contains(_new)));
    expect(out.sayThis, isNot(contains('https://')));
    final now = await recorded();
    expect(now.agentOrigin, _new);
    expect(now.agentAid, _aid); // the identity never changes, only where it is
  });

  test(
      'a lead whose key history names ANOTHER identifier is refused, and the '
      'record is untouched', () async {
    world
      ..alive.add(_impostor)
      ..keyHistoryProves[_impostor] = 'EANOTHERORG'
      ..recognisesUs[_impostor] = _aid;
    final out = await finder
        .findAgain(current: await recorded(), hints: const [_impostor]);
    expect(out.couldNotBeFound, isTrue);
    expect(out.reasons.last,
        contains('could not show that it is this organisation'));
    expect((await recorded()).agentOrigin, _old);
  });

  test(
      'a copy of the public key history is not enough: the agent must also '
      'recognise this computer', () async {
    world
      ..alive.add(_new)
      ..keyHistoryProves[_new] = _aid; // public, anybody can serve it
    final out =
        await finder.findAgain(current: await recorded(), hints: const [_new]);
    expect(out.couldNotBeFound, isTrue);
    expect(out.reasons.single, contains('does not recognise this computer'));
    expect((await recorded()).agentOrigin, _old);
  });

  test('an agent that recognises us but says it is somebody else is refused',
      () async {
    world
      ..alive.add(_impostor)
      ..keyHistoryProves[_impostor] = _aid
      ..recognisesUs[_impostor] = 'EANOTHERORG';
    final out = await finder
        .findAgain(current: await recorded(), hints: const [_impostor]);
    expect(out.couldNotBeFound, isTrue);
    expect((await recorded()).agentOrigin, _old);
  });

  test('a lead that is not https (or this computer) is never fetched',
      () async {
    world.alive.add('http://evil.example.test');
    final out = await finder.findAgain(
        current: await recorded(),
        hints: const ['http://evil.example.test', 'https://user:pw@x.test']);
    expect(out.couldNotBeFound, isTrue);
    expect(world.seen.where((r) => r.url.host == 'evil.example.test'), isEmpty);
  });

  test(
      'the first proven lead wins, and a refused lead before it does not stop '
      'the search', () async {
    world
      ..alive.addAll([_impostor, _new])
      ..keyHistoryProves[_impostor] = 'EANOTHERORG'
      ..keyHistoryProves[_new] = _aid
      ..recognisesUs[_new] = _aid;
    final out = await finder
        .findAgain(current: await recorded(), hints: const [_impostor, _new]);
    expect(out.moved, isTrue);
    expect((await recorded()).agentOrigin, _new);
  });

  test('at launch, the core is told the NEW address, not the dead one',
      () async {
    world
      ..alive.add(_new)
      ..keyHistoryProves[_new] = _aid
      ..recognisesUs[_new] = _aid;
    final checked = Completer<WhereTheAgentWent>();
    await pointThisAppAtItsAgent(
      using: world.client(),
      whereItMayHaveGone: () async => [_new],
      onChecked: checked.complete,
    );
    final out = await checked.future;
    expect(out.moved, isTrue);
    expect(AgentConfig.agentOrigin, _new);
    final told = world.seen
        .lastWhere((r) => r.url.path == '/api/controller/front-end-for');
    expect((jsonDecode(told.body) as Map)['agent_url'], _new);
  });

  test('at launch with nothing found, the app still starts and says so',
      () async {
    final checked = Completer<WhereTheAgentWent>();
    await pointThisAppAtItsAgent(
      using: world.client(),
      whereItMayHaveGone: () async => [_impostor],
      onChecked: checked.complete,
    );
    final out = await checked.future;
    expect(out.couldNotBeFound || out.couldNotBeReached, isTrue);
    expect(out.sayThis, isNotEmpty);
    expect(AgentConfig.agentOrigin, _old);
  });

  test(
      'an address that cannot be reached at all is NOT said to have moved: '
      'this computer may be offline', () async {
    // Nothing is alive: the recorded address and the lead both fail to connect.
    final out =
        await finder.findAgain(current: await recorded(), hints: const [_new]);
    expect(out.moved, isFalse);
    expect(out.couldNotBeFound, isFalse);
    expect(out.couldNotBeReached, isTrue);
    expect(out.sayThis, isNot(contains('moved')));
    expect(out.sayThis, contains('online'));
    expect((await recorded()).agentOrigin, _old);
  });

  test(
      'a relay that is up while the machine behind it is off is also '
      'unreachable, not gone', () async {
    world.machineOff.add(_old);
    final out = await finder.findAgain(current: await recorded());
    expect(out.couldNotBeReached, isTrue);
  });

  test('an address that answers with something that is not the agent is gone',
      () async {
    world.notAnAgent.add(_old);
    final out = await finder.findAgain(current: await recorded());
    expect(out.couldNotBeFound, isTrue);
    expect(out.sayThis, contains('whoever moved it'));
    expect(out.sayThis, isNot(contains('https://')));
  });

  test('an address typed without a scheme is understood', () async {
    world
      ..alive.add(_new)
      ..keyHistoryProves[_new] = _aid
      ..recognisesUs[_new] = _aid;
    final out = await finder.findAgain(
        current: await recorded(), hints: const ['box.example.test']);
    expect(out.moved, isTrue);
  });

  test('refusals are in words: no identifier, no scheme, no key history',
      () async {
    world
      ..alive.add(_impostor)
      ..keyHistoryProves[_impostor] = 'EANOTHERORG'
      ..recognisesUs[_impostor] = _aid;
    final out = await finder
        .findAgain(current: await recorded(), hints: const [_impostor]);
    for (final r in out.reasons) {
      expect(r, isNot(contains('https://')));
      expect(r, isNot(contains('EANOTHERORG')));
      expect(r, isNot(contains('key history')));
    }
  });

  test(
      'at launch the app does not wait for a dead address: the look runs '
      'behind it', () async {
    world.holdDeadHosts = Completer<void>(); // dead hosts hang until released
    final checked = Completer<WhereTheAgentWent>();
    final started = await pointThisAppAtItsAgent(
      using: world.client(),
      onChecked: checked.complete,
    ).timeout(const Duration(seconds: 2)); // returns while the look is pending
    expect(started.stillToCheck, isTrue);
    expect(AgentConfig.agentOrigin, _old);
    expect(checked.isCompleted, isFalse);

    world.holdDeadHosts!.complete();
    final out = await checked.future;
    expect(out.couldNotBeReached, isTrue);
  });

  test('a move found behind the app re-points the app and the core', () async {
    world
      ..alive.add(_new)
      ..keyHistoryProves[_new] = _aid
      ..recognisesUs[_new] = _aid;
    final checked = Completer<WhereTheAgentWent>();
    await pointThisAppAtItsAgent(
      using: world.client(),
      whereItMayHaveGone: () async => [_new],
      onChecked: checked.complete,
    );
    final out = await checked.future;
    expect(out.moved, isTrue);
    expect(AgentConfig.agentOrigin, _new);
    final told = world.seen
        .lastWhere((r) => r.url.path == '/api/controller/front-end-for');
    expect((jsonDecode(told.body) as Map)['agent_url'], _new);
  });

  test('a profile switched away from while the proof ran is NOT re-pointed',
      () async {
    world
      ..alive.add(_new)
      ..keyHistoryProves[_new] = _aid
      ..recognisesUs[_new] = _aid;
    final out = await finder.findAgain(
        current: await recorded(),
        hints: const [_new],
        stillTheSameProfile: () => false);
    expect(out.moved, isFalse);
    expect((await recorded()).agentOrigin, _old);
  });

  test("a proxy's 52x for a machine that is off is unreachable, not gone",
      () async {
    world.machineOff.add(_old);
    world.statusForMachineOff = 522;
    final out = await finder.findAgain(current: await recorded());
    expect(out.couldNotBeReached, isTrue);
  });

  group('an address is believed only when the organisation signed it', () {
    Future<WhereTheAgentWent> tryAt(String at) async =>
        finder.findAgain(current: await recorded(), hints: [at]);

    test(
        'a host that forwards everything to the real agent but is not in the '
        'record is refused, and the app is not re-pointed', () async {
      // A reverse proxy: its key history is the real one, and it relays the
      // real agent's answer to this computer too.
      world
        ..alive.addAll([_impostor, _new])
        ..keyHistoryProves[_impostor] = _aid
        ..recognisesUs[_impostor] = _aid;
      final out = await tryAt(_impostor);
      expect(out.moved, isFalse);
      expect(out.reasons.join(' '),
          contains('is not the one the organisation signed'));
      expect((await recorded()).agentOrigin, _old);
      // And it was never asked to recognise this computer, so nothing signed
      // was sent to it.
      expect(
          world.seen.where((r) =>
              r.url.host == 'impostor.example.test' &&
              r.url.path == '/api/controller/agent'),
          isEmpty);
    });

    test('with no signed record at all, nothing is accepted', () async {
      world
        ..witnessHolds.clear()
        ..alive.add(_new)
        ..keyHistoryProves[_new] = _aid
        ..recognisesUs[_new] = _aid;
      final out = await tryAt(_new);
      expect(out.moved, isFalse);
      expect(out.reasons.join(' '),
          contains('no address signed by the organisation'));
      expect((await recorded()).agentOrigin, _old);
    });

    test('a record older than one already held is refused', () async {
      world
        ..alive.add(_new)
        ..keyHistoryProves[_new] = _aid
        ..recognisesUs[_new] = _aid;
      expect((await tryAt(_new)).moved, isTrue); // holds the 2026-11-01 record
      await WhichHalfThisAppIsRunning.pointAt(
          agentOrigin: _old, agentAid: _aid);
      // The organisation later moved on; a witness that is stale now offers the
      // earlier record again (a host that has since been handed to somebody).
      final newer = _record(_originOf(_impostor), '2026-11-02T10:00:00Z');
      world.witnessHolds
        ..clear()
        ..add(newer);
      world
        ..alive.add(_impostor)
        ..keyHistoryProves[_impostor] = _aid
        ..recognisesUs[_impostor] = _aid;
      expect((await tryAt(_impostor)).moved, isTrue); // newest is kept
      await WhichHalfThisAppIsRunning.pointAt(
          agentOrigin: _old, agentAid: _aid);
      world.witnessHolds
        ..clear()
        ..add(_record(_originOf(_new), '2026-11-01T10:00:00Z'));
      final out = await tryAt(_new);
      expect(out.moved, isFalse);
      expect(out.reasons.join(' '),
          contains('older than one this app already holds'));
      expect((await recorded()).agentOrigin, _old);
    });

    test('a record signed by a rotated-out key is refused', () async {
      world
        ..witnessHolds.clear()
        ..witnessHolds.add(_record(_originOf(_new), '2026-11-03T10:00:00Z',
            signer: _rotatedOutKey))
        ..alive.add(_new)
        ..keyHistoryProves[_new] = _aid
        ..recognisesUs[_new] = _aid;
      final out = await tryAt(_new);
      expect(out.moved, isFalse);
      expect(out.reasons.join(' '),
          contains('not signed by the organisation\'s current key'));
      expect((await recorded()).agentOrigin, _old);
    });

    test('a withdrawal is not an address', () async {
      world
        ..witnessHolds.clear()
        ..witnessHolds.add(_record('', '2026-11-03T10:00:00Z'))
        ..alive.add(_new)
        ..keyHistoryProves[_new] = _aid
        ..recognisesUs[_new] = _aid;
      final out = await tryAt(_new);
      expect(out.moved, isFalse);
      expect(out.reasons.join(' '), contains('reached nowhere'));
    });

    test('the signed record is the lead: it is followed with nothing typed',
        () async {
      world
        ..alive.add(_new)
        ..keyHistoryProves[_new] = _aid
        ..recognisesUs[_new] = _aid;
      final out = await finder.findAgain(current: await recorded());
      expect(out.moved, isTrue);
      expect((await recorded()).agentOrigin, _new);
    });
  });
}
