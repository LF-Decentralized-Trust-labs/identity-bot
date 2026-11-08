import 'dart:convert';
import 'dart:io';

import 'package:agent_client/config/agent_config.dart';
import 'package:agent_client/services/core_service.dart';
import 'package:test/test.dart';

/// Asking the app that issued an invite for what it published against it.
/// Pairs with the core's route of the same name; these pin the client's side of
/// the wire: where the call goes, that it names no address, and how each answer
/// is read.
void main() {
  late HttpServer agent;
  late List<({String method, String path, String body})> seen;
  late int status;
  late String reply;
  final defaultPort = AgentConfig.desktopPort;

  setUp(() async {
    seen = [];
    status = 202;
    reply = '{"ready":false}';
    agent = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    agent.listen((req) async {
      seen.add((
        method: req.method,
        path: req.uri.path,
        body: await utf8.decoder.bind(req).join()
      ));
      req.response
        ..statusCode = status
        ..write(reply);
      await req.response.close();
    });
    AgentConfig.desktopPort = agent.port;
  });

  tearDown(() async {
    AgentConfig.desktopPort = defaultPort;
    await agent.close(force: true);
  });

  test('nothing published yet reads as null, not as an error', () async {
    final core = CoreService();
    addTearDown(core.dispose);
    expect(await core.whatTheInvitingAppPublished('tok'), isNull);
    expect(seen.single.method, 'POST');
    expect(seen.single.path, '/api/redeemed-invites/published');
    expect(jsonDecode(seen.single.body)['invite_token'], 'tok');
  });

  test('what was published is handed back as the inviting app wrote it',
      () async {
    status = 200;
    reply = jsonEncode({
      'ready': true,
      'published': {'agent_url': 'https://box.example', 'adoption_code': 'A-1'}
    });
    final core = CoreService();
    addTearDown(core.dispose);
    final got = await core.whatTheInvitingAppPublished('tok');
    expect(got!['agent_url'], 'https://box.example');
    expect(got['adoption_code'], 'A-1');
  });

  test('the code is never in the path, and no address is named', () async {
    final core = CoreService();
    addTearDown(core.dispose);
    await core.whatTheInvitingAppPublished('secret-code');
    expect(seen.single.path, isNot(contains('secret-code')));
    expect((jsonDecode(seen.single.body) as Map).keys, ['invite_token']);
  });

  test('a refusal stops the poll with its reason', () async {
    status = 410;
    reply = "this invitation's window has ended";
    final core = CoreService();
    addTearDown(core.dispose);
    expect(
        core.whatTheInvitingAppPublished('tok'),
        throwsA(predicate((e) =>
            e is InvitingAppRefused &&
            !e.retryable &&
            '$e'.contains('window has ended'))));
  });

  test('a failure on the way is worth asking again after', () async {
    status = 502;
    reply = 'the inviting app could not be reached';
    final core = CoreService();
    addTearDown(core.dispose);
    expect(core.whatTheInvitingAppPublished('tok'),
        throwsA(predicate((e) => e is InvitingAppRefused && e.retryable)));
  });
}
