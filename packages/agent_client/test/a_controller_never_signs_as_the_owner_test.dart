import 'dart:io';
import 'dart:typed_data';

import 'package:agent_client/config/agent_config.dart';
import 'package:agent_client/services/core_service.dart';
import 'package:test/test.dart';

/// Which half this app is running decides where requests go and what signs
/// them. These are the two answers that must never be confused.
void main() {
  tearDown(() => AgentConfig.agentOrigin = '');

  test('an ordinary installation still talks to its own core', () {
    AgentConfig.agentOrigin = '';
    expect(AgentConfig.agentBaseUrl, AgentConfig.coreBaseUrl);
    expect(AgentConfig.isAController, isFalse);
    expect(CoreService().baseUrl, AgentConfig.coreBaseUrl,
        reason: 'the ordinary case must be unchanged by any of this');
  });

  test('a controller sends identity requests to the agent, not to itself', () {
    AgentConfig.agentOrigin = 'https://agent.example.test';
    expect(AgentConfig.isAController, isTrue);
    expect(CoreService().baseUrl, 'https://agent.example.test');
    expect(CoreService().baseUrl, isNot(AgentConfig.coreBaseUrl),
        reason: 'a controller asking its own core gets an answer about nobody');
  });

  test('the address of this machine stays available while in controller mode', () {
    AgentConfig.agentOrigin = 'https://agent.example.test';
    // The signing call needs it: the enclave key lives here and the agent
    // cannot reach it. Collapsing the two addresses would send the signing
    // request to the agent and nothing would ever be signed.
    expect(AgentConfig.coreBaseUrl, startsWith('http://127.0.0.1:'));
    expect(AgentConfig.coreBaseUrl, isNot(AgentConfig.agentBaseUrl));
  });

  test('a seed handed to a controller does NOT make it sign as the owner',
      () async {
    // An installation holding the identity's key is not a controller, so a seed
    // here is a mistake — and honouring it would sign as the OWNER, granting
    // everything the controller gate exists to hold back.
    //
    // Checked by watching what actually arrives, because comparing the two
    // CoreService objects proves nothing: they are the same type either way,
    // and the client is inside them.
    final seen = <HttpHeaders>[];
    final stub = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => stub.close(force: true));
    stub.listen((req) async {
      seen.add(req.headers);
      req.response
        ..statusCode = 200
        ..headers.contentType = ContentType.json
        ..write('{"status":"ok"}');
      await req.response.close();
    });

    AgentConfig.agentOrigin = 'http://127.0.0.1:${stub.port}';
    final asAController = CoreService(
      ownerSeed: () async => Uint8List.fromList(List.filled(32, 7)),
      ownerAid: 'EPretendOwner',
    );
    try {
      await asAController.getHealth();
    } catch (_) {
      // The body shape does not matter; what arrived does.
    }

    expect(seen, isNotEmpty, reason: 'the request never reached the agent');
    expect(seen.single.value('x-ia-owner-sig'), isNull,
        reason: 'a controller signed as the OWNER, which grants everything the '
            'controller gate exists to hold back');
  });

  test('an explicit baseUrl still wins, so reaching a third party is unaffected', () {
    AgentConfig.agentOrigin = 'https://agent.example.test';
    expect(CoreService(baseUrl: 'https://someone-else.example.test').baseUrl,
        'https://someone-else.example.test');
  });
}
