import 'dart:convert';

import 'package:agent_client/services/the_organisations_ai_agents.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

// The JSON below is what the AI-agent add-on's handleListAgents sends
// (identity-agent-addons/aiagents/mcp_agents.go, agentView), keys and shapes
// as encoded there; the first is an agent with a sign-in and a limit, the
// second a revoked one with nothing optional.
const _live = {
  'asset_id': 'asset-1',
  'name': 'Scribe',
  'agent_aid': 'EAGENT1',
  'delegator_aid': 'EOWNER',
  'capabilities': ['agent.message.send', 'files.read'],
  'resource_constraints': {
    'agent.message.send': {
      'to': ['EAGENT2']
    }
  },
  'agent_config': {
    'role': 'Writes the minutes',
    'brain': {
      'kind': 'api_key',
      'provider': 'openrouter',
      'model': 'm/x',
      'program': ''
    },
    'exposure': {'mcp': true, 'direct_api': false},
  },
  'brain_sign_in': {
    'kind': 'api_key',
    'provider': 'openrouter',
    'stays_with_identity_agent': true
  },
  'status': 'active',
  'created_at': '2026-10-01T09:30:00Z',
  'grant_pending': true,
};

const _gone = {
  'asset_id': 'asset-2',
  'name': 'Old',
  'agent_aid': 'EAGENT2',
  'delegator_aid': 'EOWNER',
  'capabilities': <String>[],
  'resource_constraints': <String, dynamic>{},
  'status': 'revoked',
  'created_at': '2026-09-01T00:00:00Z',
  'revoked_at': '2026-10-02T10:00:00Z',
  'revoked_by': 'EOWNER',
};

AiAgentRoster rosterSaying(int status, Object body, {List<Uri>? asked}) =>
    AiAgentRoster(
        MockClient((r) async {
          asked?.add(r.url);
          return http.Response(body is String ? body : jsonEncode(body), status,
              headers: {'content-type': 'application/json'});
        }),
        'http://core');

void main() {
  test('every key the core sends is read as the core names it', () async {
    final asked = <Uri>[];
    final got = await rosterSaying(200, {
      'agents': [_live, _gone]
    }, asked: asked)
        .list();
    expect(asked.single.toString(), 'http://core/api/mcp/agents');
    expect(got.map((a) => a.assetId), ['asset-1', 'asset-2']);
    final a = got.first;
    expect(a.name, 'Scribe');
    expect(a.agentAid, 'EAGENT1');
    expect(a.delegatorAid, 'EOWNER');
    expect(a.capabilities, ['agent.message.send', 'files.read']);
    expect(a.role, 'Writes the minutes');
    expect(a.brain['model'], 'm/x');
    expect(a.brainSignInProvider, 'openrouter');
    expect(a.brainStaysWithIdentityAgent, isTrue);
    expect(a.grantPending, isTrue);
    expect(a.createdAt!.toUtc().hour, 9);
    expect((a.resourceConstraints!['agent.message.send'] as Map)['to'],
        ['EAGENT2']);
    expect(a.cannotActNow, isFalse);
    expect(a.revokedForGood, isFalse);
  });

  test('a revoked agent says so, and when and by whom', () async {
    final got = (await rosterSaying(200, {
      'agents': [_gone]
    }).list())
        .single;
    expect(got.cannotActNow, isTrue);
    expect(got.revokedForGood, isTrue);
    expect(got.revokedBy, 'EOWNER');
    expect(got.revokedAt!.toUtc().day, 2);
    expect(got.brainSignIn, isNull);
    expect(got.brain, isEmpty);
    expect(got.resourceConstraints, isEmpty);
  });

  test('a withdrawn grant cannot act but is not revoked for good', () async {
    final got = (await rosterSaying(200, {
      'agents': [
        {..._live, 'status': 'revoked'}
      ]
    }).list())
        .single;
    expect(got.cannotActNow, isTrue);
    expect(got.revokedForGood, isFalse);
  });

  test('a core too old to report limits is told from one that reports none',
      () async {
    final old = Map<String, dynamic>.from(_live)..remove('resource_constraints');
    final got = await rosterSaying(200, {
      'agents': [old, _gone]
    }).list();
    expect(got[0].resourceConstraints, isNull);
    expect(got[1].resourceConstraints, isEmpty);
  });

  test('an empty roster is nobody, not a failure', () async {
    expect(await rosterSaying(200, {'agents': <Object>[]}).list(), isEmpty);
  });

  test('an entry that cannot be addressed is left out', () async {
    final got = await rosterSaying(200, {
      'agents': [
        _live,
        {'name': 'no id'},
        'junk',
        {'asset_id': ''}
      ]
    }).list();
    expect(got.map((a) => a.assetId), ['asset-1']);
  });

  test('a roster that cannot be read says so and is not nobody', () async {
    expect(rosterSaying(503, {'error': 'down'}).list(),
        throwsA(isA<AiAgentRosterException>()
            .having((e) => e.statusCode, 'statusCode', 503)
            .having((e) => e.response!.body, 'refusal as it came',
                contains('down'))));
    expect(rosterSaying(200, 'not json').list(),
        throwsA(isA<AiAgentRosterException>()));
    expect(rosterSaying(200, {'agents': 'x'}).list(),
        throwsA(isA<AiAgentRosterException>()));
    expect(rosterSaying(200, [_live]).list(),
        throwsA(isA<AiAgentRosterException>()));
    expect(await rosterSaying(500, {}).tryList(), isNull);
    final unreachable = AiAgentRoster(
        MockClient((_) async => throw http.ClientException('no route')),
        'http://core');
    expect(unreachable.list(), throwsA(isA<AiAgentRosterException>()));
  });

  test('one agent is read by its asset id, and absent is null', () async {
    final r = rosterSaying(200, {
      'agents': [_live, _gone]
    });
    expect((await r.read('asset-2'))!.name, 'Old');
    expect(await r.read('nobody'), isNull);
  });
}
