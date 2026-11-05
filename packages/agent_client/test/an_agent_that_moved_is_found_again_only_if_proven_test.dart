import 'dart:convert';

import 'package:agent_client/config/agent_config.dart';
import 'package:agent_client/services/finding_an_agent_that_moved.dart';
import 'package:agent_client/services/point_this_app_at_its_agent.dart';
import 'package:agent_client/services/which_half_this_app_is_running.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

/// An organisation that changed address is found again, but only at an address
/// proven to be the same organisation.
///
/// The case that started this: the app was recorded against a quick-tunnel URL;
/// the organisation then moved to a stable relay name. The old address was dead,
/// the app pushed it to its core at every launch, and opening the organisation
/// failed with an error that named no cause.
const _aid = 'EORGANISATION';
const _old = 'https://old-tunnel.example.test';
const _new = 'https://grape-dev.example.test';
const _impostor = 'https://impostor.example.test';

/// A small world: which hosts are alive, which identifier each one's published
/// key history proves, and which of them recognise this computer.
class _World {
  final alive = <String>{};
  final keyHistoryProves = <String, String>{};
  final recognisesUs = <String, String>{}; // host -> identifier it answers with
  final seen = <http.Request>[];

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
                  jsonEncode({'verified': false, 'why': 'that history names '
                      '${proves ?? 'nobody'}'}),
                  200);
            }
            return http.Response(
                jsonEncode({'verified': true, 'aid': proves, 'public_key': 'D'}),
                200);
          }
          return http.Response('{}', 200); // front-end-for etc.
        }
        if (!alive.contains(host)) throw http.ClientException('no route', req.url);
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
    world = _World();
    await WhichHalfThisAppIsRunning.pointAt(agentOrigin: _old, agentAid: _aid);
    finder = FindingAnAgentThatMoved(client: world.client());
  });
  tearDown(() {
    AgentConfig.agentOrigin = '';
    AgentConfig.agentAid = '';
  });

  Future<WhichHalfThisAppIsRunning> recorded() => WhichHalfThisAppIsRunning.now();

  test('an agent that still answers is left exactly where it is', () async {
    world.alive.add(_old);
    final out = await finder.findAgain(
        current: await recorded(), hints: const [_new]);
    expect(out.moved, isFalse);
    expect(out.sayThis, isEmpty);
    expect((await recorded()).agentOrigin, _old);
  });

  test('a dead address is replaced by a lead whose key history proves the same '
      'identifier AND which recognises this computer', () async {
    world
      ..alive.add(_new)
      ..keyHistoryProves[_new] = _aid
      ..recognisesUs[_new] = _aid;
    final out = await finder.findAgain(
        current: await recorded(), hints: const [_new]);
    expect(out.moved, isTrue);
    expect(out.sayThis, contains(_old));
    expect(out.sayThis, contains(_new));
    final now = await recorded();
    expect(now.agentOrigin, _new);
    expect(now.agentAid, _aid); // the identity never changes, only where it is
  });

  test('a lead whose key history names ANOTHER identifier is refused, and the '
      'record is untouched', () async {
    world
      ..alive.add(_impostor)
      ..keyHistoryProves[_impostor] = 'EANOTHERORG'
      ..recognisesUs[_impostor] = _aid;
    final out = await finder.findAgain(
        current: await recorded(), hints: const [_impostor]);
    expect(out.couldNotBeFound, isTrue);
    expect(out.reasons.single, contains('did not prove it is this organisation'));
    expect((await recorded()).agentOrigin, _old);
  });

  test('a copy of the public key history is not enough: the agent must also '
      'recognise this computer', () async {
    world
      ..alive.add(_impostor)
      ..keyHistoryProves[_impostor] = _aid; // public, anybody can serve it
    final out = await finder.findAgain(
        current: await recorded(), hints: const [_impostor]);
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
    final out = await finder.findAgain(
        current: await recorded(), hints: const [_impostor]);
    expect(out.couldNotBeFound, isTrue);
    expect((await recorded()).agentOrigin, _old);
  });

  test('a lead that is not https (or this computer) is never fetched', () async {
    world.alive.add('http://evil.example.test');
    final out = await finder.findAgain(
        current: await recorded(),
        hints: const ['http://evil.example.test', 'https://user:pw@x.test']);
    expect(out.couldNotBeFound, isTrue);
    expect(world.seen.where((r) => r.url.host == 'evil.example.test'), isEmpty);
  });

  test('the first proven lead wins, and a refused lead before it does not stop '
      'the search', () async {
    world
      ..alive.addAll([_impostor, _new])
      ..keyHistoryProves[_impostor] = 'EANOTHERORG'
      ..keyHistoryProves[_new] = _aid
      ..recognisesUs[_new] = _aid;
    final out = await finder.findAgain(
        current: await recorded(), hints: const [_impostor, _new]);
    expect(out.moved, isTrue);
    expect((await recorded()).agentOrigin, _new);
  });

  test('at launch, the core is told the NEW address, not the dead one',
      () async {
    world
      ..alive.add(_new)
      ..keyHistoryProves[_new] = _aid
      ..recognisesUs[_new] = _aid;
    final out = await pointThisAppAtItsAgent(
      using: world.client(),
      whereItMayHaveGone: () async => [_new],
    );
    expect(out.moved, isTrue);
    expect(AgentConfig.agentOrigin, _new);
    final told = world.seen
        .lastWhere((r) => r.url.path == '/api/controller/front-end-for');
    expect((jsonDecode(told.body) as Map)['agent_url'], _new);
  });

  test('at launch with nothing found, the app still starts and says so',
      () async {
    final out = await pointThisAppAtItsAgent(
      using: world.client(),
      whereItMayHaveGone: () async => [_impostor],
    );
    expect(out.couldNotBeFound, isTrue);
    expect(out.sayThis, contains('find it again'));
    expect(AgentConfig.agentOrigin, _old);
  });
}
