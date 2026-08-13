import 'dart:convert';
import 'dart:io';

import 'package:agent_client/services/core_service.dart';
import 'package:test/test.dart';

/// Founding an organisation goes through the owner's own agent.
///
/// It used to go straight to the machine, with a call of its own that named an
/// owner and proved nothing about who was asking. That worked only because the
/// machine took the owner's identifier on trust; once claims had to prove who
/// makes them, every organisation founded that way was refused.
///
/// The previous test here stood up a fake machine that answered 200 to
/// anything, so it could not have caught that and did not. These assert the two
/// things that actually keep it fixed: WHERE the call goes, and that it says
/// what is being founded.
void main() {
  late HttpServer agent;
  late List<({String path, Map<String, dynamic> body})> seen;

  setUp(() async {
    seen = [];
    agent = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    agent.listen((req) async {
      final raw = await utf8.decoder.bind(req).join();
      seen.add((
        path: req.uri.path,
        body: raw.isEmpty
            ? <String, dynamic>{}
            : jsonDecode(raw) as Map<String, dynamic>,
      ));
      req.response
        ..statusCode = 200
        ..write(jsonEncode({'root_aid': 'EORGROOT'}));
      await req.response.close();
    });
  });

  tearDown(() async => agent.close(force: true));

  CoreService client() =>
      CoreService(baseUrl: 'http://127.0.0.1:${agent.port}');

  test('the claim is made through this agent, never against the machine', () async {
    final core = client();
    await core.adoptAgent(
      boxUrl: Uri.parse('http://the-machine.example:5050'),
      adoptionCode: 'CODE',
      ownerAid: 'EOWNER',
      kind: 'organisation',
    );
    core.dispose();

    expect(seen, hasLength(1));
    // Against our own agent's adopt route — the one that mints the owner,
    // takes the challenge and signs. A call to the machine's own
    // /api/pairing/complete is the shape that could not prove anything.
    expect(seen.single.path, '/api/pairing/adopt');
    expect(seen.single.body['box_url'], 'http://the-machine.example:5050');
  });

  test('it says what is being founded, so it is not filed as a computer', () async {
    final core = client();
    await core.adoptAgent(
      boxUrl: Uri.parse('http://x.example'),
      adoptionCode: 'CODE',
      kind: 'organisation',
    );
    core.dispose();
    expect(seen.single.body['kind'], 'organisation');
  });

  test('a computer is what you get if nothing is said', () async {
    final core = client();
    await core.adoptAgent(
        boxUrl: Uri.parse('http://x.example'), adoptionCode: 'CODE');
    core.dispose();
    expect(seen.single.body['kind'], 'individual');
  });
}
