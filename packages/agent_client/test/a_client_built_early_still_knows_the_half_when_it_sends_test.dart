import 'dart:async';
import 'dart:convert';

import 'package:agent_client/config/agent_config.dart';
import 'package:agent_client/services/controller_signing_client.dart';
import 'package:agent_client/services/the_agent_this_app_talks_to.dart';
import 'package:agent_client/services/the_core_is_settled.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart' as testing;
import 'package:test/test.dart';

const _agent = 'https://agent.example.test';

/// A client is built when a service is, and startup finds out which half this
/// app is later (`pointThisAppAtItsAgent`). Choosing the wrapper at build time
/// leaves the early client an ordinary one for ever.
void main() {
  tearDown(() {
    AgentConfig.agentOrigin = '';
    AgentConfig.agentAid = '';
    TheCoreIsSettled.reset();
  });

  http.Client core(List<http.BaseRequest> toAgent, List<Map<String, dynamic>> signed) =>
      testing.MockClient((req) async {
        if (req.url.path == '/api/controller/sign') {
          signed.add(jsonDecode(req.body) as Map<String, dynamic>);
          return http.Response(
              '{"controller_aid":"B","signature":"0B","timestamp":"t"}', 200);
        }
        toAgent.add(req);
        return http.Response('{}', 200);
      });

  test('a client built before the app is pointed at its agent signs for it, '
      'and uses the agent aid known when it sends', () async {
    final toAgent = <http.BaseRequest>[];
    final signed = <Map<String, dynamic>>[];
    final client = TheAgentThisAppTalksTo.clientFor(null, core(toAgent, signed));

    AgentConfig.agentOrigin = _agent;
    AgentConfig.agentAid = 'EFoundLater';
    await client.get(Uri.parse('$_agent/api/profile'));

    expect(signed.single['for'], 'EFoundLater');
    expect(toAgent.single.headers['X-IA-Controller-Sig'], '0B');
  });

  test('a client built early waits for the core and refuses when it failed',
      () async {
    final toAgent = <http.BaseRequest>[];
    final signed = <Map<String, dynamic>>[];
    final client = TheAgentThisAppTalksTo.clientFor(null, core(toAgent, signed));
    AgentConfig.agentOrigin = _agent;

    final starting = Completer<void>();
    final during = TheCoreIsSettled.during(() => starting.future);
    var done = false;
    final pending =
        client.get(Uri.parse('$_agent/api/profile')).whenComplete(() => done = true);
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(done, isFalse, reason: 'an early-built client did not wait');
    starting.complete();
    await during;
    await pending;
    expect(toAgent, hasLength(1));

    await expectLater(
        TheCoreIsSettled.during<void>(() async => throw StateError('no core')),
        throwsStateError);
    await expectLater(client.get(Uri.parse('$_agent/api/profile')),
        throwsA(isA<ThisMachineCouldNotSign>()));
    expect(toAgent, hasLength(1));
  });

  test('an ordinary installation is unchanged: nothing is asked to sign',
      () async {
    final toAgent = <http.BaseRequest>[];
    final signed = <Map<String, dynamic>>[];
    final client = TheAgentThisAppTalksTo.clientFor(null, core(toAgent, signed));
    await client.get(Uri.parse('${AgentConfig.coreBaseUrl}/api/profile'));
    expect(signed, isEmpty);
    expect(toAgent, hasLength(1));
  });
}
