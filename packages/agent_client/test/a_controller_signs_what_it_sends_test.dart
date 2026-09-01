import 'dart:convert';

import 'package:agent_client/services/controller_signing_client.dart';
import 'package:http/http.dart' as http;
import 'package:test/test.dart';

const _agent = 'https://agent.example.test';
const _localCore = 'http://127.0.0.1:49221';

/// A stand-in for this machine's core and the agent, in one handler, so a test
/// can see exactly what was asked of each.
class _Watched {
  final List<http.Request> toTheAgent = [];
  final List<Map<String, dynamic>> askedToSign = [];
  bool coreWillSign = true;

  late final _Split client = _Split(this);
}

/// Answers as this machine's core for one origin and as the agent for the rest,
/// so a test can see exactly what was asked of each.
class _Split extends http.BaseClient {
  _Split(this.w);
  final _Watched w;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final req = request as http.Request;
    if (req.url.toString().startsWith(_localCore)) {
      w.askedToSign.add(jsonDecode(req.body) as Map<String, dynamic>);
      if (!w.coreWillSign) {
        return _reply('{"error":"no hardware"}', 501);
      }
      return _reply(
        jsonEncode({
          'controller_aid': 'BThisMachine',
          'signature': '0BSignatureOverWhatWasAsked',
          'timestamp': '2026-08-31T12:00:00Z',
        }),
        200,
      );
    }
    w.toTheAgent.add(req);
    return _reply('{"ok":true}', 200);
  }

  http.StreamedResponse _reply(String body, int code) => http.StreamedResponse(
        Stream.value(utf8.encode(body)),
        code,
        headers: const {'content-type': 'application/json'},
      );
}

void main() {
  test('a request to the agent carries this machine\'s signature', () async {
    final w = _Watched();
    final c = ControllerSigningClient(
      agentOrigin: _agent,
      localCoreOrigin: _localCore,
      inner: w.client,
    );

    await c.post(Uri.parse('$_agent/api/employees/roles'), body: '{"a":1}');

    expect(w.toTheAgent, hasLength(1));
    final sent = w.toTheAgent.single;
    expect(sent.headers['X-IA-Controller-AID'], 'BThisMachine');
    expect(sent.headers['X-IA-Controller-Sig'], '0BSignatureOverWhatWasAsked');
    // Echoed from the core, never formatted again here: the moment is inside
    // the signature, so a second formatting that differs at all signs a string
    // the agent never sees.
    expect(sent.headers['X-IA-Controller-Timestamp'], '2026-08-31T12:00:00Z');
  });

  test('the core is asked to sign the path and body actually being sent', () async {
    final w = _Watched();
    final c = ControllerSigningClient(
      agentOrigin: _agent,
      localCoreOrigin: _localCore,
      inner: w.client,
    );

    await c.post(Uri.parse('$_agent/api/rotation?why=test'), body: '{"a":1}');

    expect(w.askedToSign, hasLength(1));
    final asked = w.askedToSign.single;
    expect(asked['method'], 'POST');
    // The path only. A signature over the full URL breaks the moment the same
    // agent is reached by another name, which is what a relay does.
    expect(asked['path'], '/api/rotation');
    expect(utf8.decode(base64.decode(asked['body_b64'] as String)), '{"a":1}');
  });

  test('requests anywhere else are not signed, so this machine is not '
      'named to every stranger it looks up', () async {
    final w = _Watched();
    final c = ControllerSigningClient(
      agentOrigin: _agent,
      localCoreOrigin: _localCore,
      inner: w.client,
    );

    await c.get(Uri.parse('https://someone-else.example.test/oobi/EWhoever'));

    expect(w.askedToSign, isEmpty,
        reason: 'the local core was asked to sign a request to a stranger');
    expect(w.toTheAgent.single.headers.containsKey('X-IA-Controller-AID'), isFalse);
  });

  test('a host that merely starts with the agent\'s name is not the agent', () async {
    final w = _Watched();
    final c = ControllerSigningClient(
      agentOrigin: _agent,
      localCoreOrigin: _localCore,
      inner: w.client,
    );

    await c.get(Uri.parse('https://agent.example.test.attacker.test/api/profile'));

    expect(w.askedToSign, isEmpty,
        reason: 'a prefix match handed this machine\'s signature to another host');
  });

  test('when this machine will not sign, the request goes unsigned rather '
      'than falling back to the local core for an answer', () async {
    final w = _Watched()..coreWillSign = false;
    final c = ControllerSigningClient(
      agentOrigin: _agent,
      localCoreOrigin: _localCore,
      inner: w.client,
    );

    await c.get(Uri.parse('$_agent/api/employees/roles'));

    // It still went to the AGENT, which will refuse it. What must never happen
    // is the request going to the local core and coming back with a plausible
    // answer about nobody.
    expect(w.toTheAgent, hasLength(1));
    expect(w.toTheAgent.single.url.origin, Uri.parse(_agent).origin);
    expect(w.toTheAgent.single.headers.containsKey('X-IA-Controller-Sig'), isFalse);
  });

  test('an authentication level travels only with what vouched for it', () async {
    final w = _Watched();
    final c = ControllerSigningClient(
      agentOrigin: _agent,
      localCoreOrigin: _localCore,
      inner: w.client,
      authentication: () async => VouchedAuthentication(
        level: 'high',
        at: DateTime.utc(2026, 8, 31, 11, 59),
        score: 88,
        vouchedBy: '0BTheRootDeviceSaysSo',
      ),
    );

    await c.post(Uri.parse('$_agent/api/rotation'), body: '{}');

    expect(w.askedToSign.single['auth_level'], 'high',
        reason: 'the level must be inside the signature, not beside it');
    expect(w.toTheAgent.single.headers['X-IA-Auth-Level-Vouched-By'],
        '0BTheRootDeviceSaysSo');
  });
}
