import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';
import 'package:agent_client/services/an_agent_proving_itself.dart';
import 'package:agent_client/services/what_an_agent_calls_itself.dart';

/// What somebody is shown before an agent elsewhere is remembered: a name and
/// a picture. These are the cases that decide whether the name on that screen
/// is the one the agent actually holds.
void main() {
  test('an organisation is shown by its organisation name', () {
    final calls = WhatAnAgentCallsItself.fromProfileJson(
        jsonEncode({'fn': 'Pat Doe', 'org_name': 'Example Organisation'}));
    expect(calls.name, 'Example Organisation',
        reason: 'the person recognises the organisation, not whoever filled in '
            'the form');
  });

  test('an agent with only a full name still shows something recognisable', () {
    final calls =
        WhatAnAgentCallsItself.fromProfileJson(jsonEncode({'fn': 'Pat Doe'}));
    expect(calls.name, 'Pat Doe');
  });

  test('a picture is read from a data URL or from bare base64', () {
    final bytes = base64Encode([1, 2, 3, 4]);
    expect(
        WhatAnAgentCallsItself.fromProfileJson(
                jsonEncode({'fn': 'A', 'photo': 'data:image/png;base64,$bytes'}))
            .picture,
        [1, 2, 3, 4]);
    expect(
        WhatAnAgentCallsItself.fromProfileJson(
                jsonEncode({'fn': 'A', 'photo': bytes}))
            .picture,
        [1, 2, 3, 4]);
  });

  test('a picture that does not decode costs the picture, not the name', () {
    final calls = WhatAnAgentCallsItself.fromProfileJson(
        jsonEncode({'org_name': 'Example Organisation', 'photo': '%%%not base64'}));
    expect(calls.picture, isNull);
    expect(calls.name, 'Example Organisation');
  });

  test('an agent that has been given nothing is shown as nothing, not as an error',
      () {
    final calls = WhatAnAgentCallsItself.fromProfileJson('{}');
    expect(calls.name, isEmpty);
    expect(calls.picture, isNull);
  });

  group('reading it, after proving it', () {
    const localCore = 'http://127.0.0.1:5050';
    const agent = 'https://box.example.test';
    const proved = {'verified': true, 'aid': 'EMYIDENTITY', 'public_key': 'DK'};

    MockClient core(List<Map<String, dynamic>> answers,
        List<Map<String, dynamic>> asked) {
      var n = 0;
      return MockClient((req) async {
        if (req.url.path == '/api/verify/agent-at-address') {
          asked.add(jsonDecode(req.body) as Map<String, dynamic>);
          return http.Response(
              jsonEncode(answers[n < answers.length ? n++ : n - 1]), 200);
        }
        if (req.url.path == '/api/controller/sign') {
          return http.Response(
              jsonEncode({
                'controller_aid': 'BTHISMACHINE',
                'signature': '0BSIG',
                'timestamp': '2026-09-01T00:00:00Z',
              }),
              200);
        }
        return http.Response(jsonEncode({'org_name': 'Example Organisation'}), 200);
      });
    }

    test('the proof is held to what was proved first', () async {
      final asked = <Map<String, dynamic>>[];
      final calls = await readWhatAnAgentCallsItself(
          agentOrigin: agent,
          agentAid: 'EMYIDENTITY',
          knownSequence: 7,
          knownKey: 'DK',
          localCoreOrigin: localCore,
          inner: core([proved], asked));
      expect(calls.name, 'Example Organisation');
      expect(asked.single['known_sequence'], 7);
      expect(asked.single['known_key'], 'DK');
    });

    test('a passing blip is asked again, and a verdict is not', () async {
      final asked = <Map<String, dynamic>>[];
      final calls = await readWhatAnAgentCallsItself(
          agentOrigin: agent,
          agentAid: 'EMYIDENTITY',
          localCoreOrigin: localCore,
          blipPause: const Duration(milliseconds: 1),
          inner: core([
            {'verified': false, 'kind': 'no-answer'},
            proved
          ], asked));
      expect(calls.name, 'Example Organisation');
      expect(asked, hasLength(2));

      final again = <Map<String, dynamic>>[];
      await expectLater(
          readWhatAnAgentCallsItself(
              agentOrigin: agent,
              agentAid: 'EMYIDENTITY',
              localCoreOrigin: localCore,
              blipPause: const Duration(milliseconds: 1),
              inner: core([
                {'verified': false, 'kind': 'different'},
                proved
              ], again)),
          throwsA(isA<AnAgentCouldNotBeProved>()));
      expect(again, hasLength(1));
    });
  });
}
