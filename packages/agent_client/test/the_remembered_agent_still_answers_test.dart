import 'dart:convert';

import 'package:agent_client/services/the_remembered_agent_still_answers.dart';
import 'package:agent_client/services/which_half_this_app_is_running.dart';
import 'package:test/test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// On launch the remembered agent is proved again, against the identifier that
/// was stored. Only a different agent stops the app.
void main() {
  const core = 'http://127.0.0.1:5050';

  Future<void> remember() async {
    SharedPreferences.setMockInitialValues({});
    await WhichHalfThisAppIsRunning.pointAt(
        agentOrigin: 'https://box.example.test', agentAid: 'EMINE');
  }

  http.Client coreSaying(Map<String, dynamic> a, {void Function(Map)? seen}) =>
      MockClient((req) async {
        seen?.call(jsonDecode(req.body) as Map);
        return http.Response(jsonEncode(a), 200);
      });

  test('an installation that holds its own identity has nothing to check',
      () async {
    SharedPreferences.setMockInitialValues({});
    expect(await checkTheRememberedAgent(localCoreOrigin: core,
            client: MockClient((_) async => fail('asked'))),
        TheRememberedAgent.nothingRemembered);
  });

  test('the same agent answering is still there, asked for the STORED identifier',
      () async {
    await remember();
    Map? asked;
    final r = await checkTheRememberedAgent(
        localCoreOrigin: core,
        client: coreSaying(
            {'verified': true, 'aid': 'EMINE', 'public_key': 'DK'},
            seen: (b) => asked = b));
    expect(r, TheRememberedAgent.stillThere);
    expect(asked!['aid'], 'EMINE');
    expect(asked!['address'], 'https://box.example.test');
  });

  test('a different agent at the address stops the app', () async {
    await remember();
    expect(
        await checkTheRememberedAgent(
            localCoreOrigin: core,
            client: coreSaying({
              'verified': false,
              'kind': 'different',
              'why': 'not the one'
            })),
        TheRememberedAgent.somethingElseAnswers);
  });

  test('a verified answer for another identifier is a different agent',
      () async {
    await remember();
    expect(
        await checkTheRememberedAgent(
            localCoreOrigin: core,
            client: coreSaying(
                {'verified': true, 'aid': 'EOTHER', 'public_key': 'DK'})),
        TheRememberedAgent.somethingElseAnswers);
  });

  test('nothing answering does not lock anybody out', () async {
    await remember();
    expect(
        await checkTheRememberedAgent(
            localCoreOrigin: core,
            client: coreSaying({'verified': false, 'kind': 'no-answer'})),
        TheRememberedAgent.cannotTell);
  });

  test('a core that cannot check is not a verdict either', () async {
    await remember();
    expect(
        await checkTheRememberedAgent(
            localCoreOrigin: core,
            client: MockClient((_) async => http.Response('no engine', 501))),
        TheRememberedAgent.cannotTell);
  });
}
