import 'dart:convert';
import 'dart:io';

import 'package:agent_client/config/agent_config.dart';
import 'package:agent_client/services/point_this_app_at_its_agent.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

/// Pointing the app also tells the core on this computer which half it is
/// running.
///
/// The app knowing is not enough. A core with no identity answers every
/// question about one correctly and about nobody — not initialized, no
/// credentials, an empty roster — so a screen still calling this machine shows
/// that as the person's own and nothing reports a problem. The core has to be
/// told before it can refuse.
///
/// The symmetrical case matters as much: an installation that stopped being a
/// front end and left the record behind would be locked out of the identity it
/// now holds, by its own safety net, with a refusal naming an agent that is no
/// longer anything to do with it.
void main() {
  late List<http.Request> seen;
  late http.Client client;

  setUp(() {
    seen = [];
    client = MockClient((req) async {
      seen.add(req);
      return http.Response('{}', 200);
    });
  });

  http.Request theOneAbout(List<http.Request> rs) =>
      rs.singleWhere((r) => r.url.path == '/api/controller/front-end-for');

  test('it is told, when this app becomes a front end', () async {
    await tellThisComputerWhichHalfItIsRunning(
      agentAid: 'EAGENT',
      agentOrigin: 'https://box.example.test',
      using: client,
    );

    final told = theOneAbout(seen);
    expect(told.method, 'POST');
    final body = jsonDecode(told.body) as Map<String, dynamic>;
    // Both, always. An address alone would leave the core naming an agent it
    // cannot tell apart from whatever answers there.
    expect(body['agent_aid'], 'EAGENT');
    expect(body['agent_url'], 'https://box.example.test');
    // Its own core, never the agent. The record is about THIS computer, and
    // writing it on the agent would say something false about a machine that
    // does hold the identity.
    expect(told.url.toString(),
        startsWith('${AgentConfig.coreBaseUrl}/api/controller/front-end-for'));
  });

  test('and it is untold, when this app holds the identity itself', () async {
    await tellThisComputerWhichHalfItIsRunning(
      agentAid: '',
      agentOrigin: '',
      using: client,
    );

    expect(theOneAbout(seen).method, 'DELETE');
  });

  test('a core that cannot be reached does not stop the app starting',
      () async {
    final broken = MockClient((_) async => throw const SocketException('no'));
    // What a failure costs is the safety net, not the behaviour: the app is
    // pointed at its agent by the caller before this runs.
    await tellThisComputerWhichHalfItIsRunning(
      agentAid: 'EAGENT',
      agentOrigin: 'https://box.example.test',
      using: broken,
    );
  });
}
