import 'dart:convert';

import 'package:agent_client/services/profile_scope.dart';
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

  test('nothing answering is not an answer, and the gate shows nothing for it', () async {
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

  /// What the first version of the flow wrote: an origin as typed, straight
  /// into the profile's settings, with no tidying and no https rule.
  Future<void> storedByTheOldFlow(String origin) async {
    SharedPreferences.setMockInitialValues({});
    final scope = await ProfileScope.activeId();
    SharedPreferences.setMockInitialValues({
      '$scope.controller_agent_origin': origin,
      '$scope.controller_agent_aid': 'EMINE',
    });
  }

  test('a stored plain http address to another host is never asked', () async {
    await storedByTheOldFlow('http://203.0.113.9:5151');
    expect((await WhichHalfThisAppIsRunning.now()).agentOrigin,
        'http://203.0.113.9:5151');
    expect(
        await checkTheRememberedAgent(
            localCoreOrigin: core,
            client: MockClient(
                (_) async => fail('a plain http address was asked'))),
        TheRememberedAgent.addressNotSecure);
  });

  test('a stored address with a trailing slash is tidied before it is proved',
      () async {
    await storedByTheOldFlow('https://box.example.test/');
    Map? asked;
    final r = await checkTheRememberedAgent(
        localCoreOrigin: core,
        client: coreSaying(
            {'verified': true, 'aid': 'EMINE', 'public_key': 'DK'},
            seen: (b) => asked = b));
    expect(r, TheRememberedAgent.stillThere);
    expect(asked!['address'], 'https://box.example.test');
  });

  test('the proved key state is kept, and handed back on the next check',
      () async {
    await remember();
    final bodies = <Map>[];
    http.Client saying(int seq, String key) => coreSaying(
        {'verified': true, 'aid': 'EMINE', 'public_key': key, 'sequence': seq},
        seen: bodies.add);
    await checkTheRememberedAgent(localCoreOrigin: core, client: saying(4, 'DK4'));
    expect(bodies.last.containsKey('known_sequence'), isFalse);
    await checkTheRememberedAgent(localCoreOrigin: core, client: saying(5, 'DK5'));
    expect(bodies.last['known_sequence'], 4);
    expect(bodies.last['known_key'], 'DK4');
    final half = await WhichHalfThisAppIsRunning.now();
    expect(half.agentSequence, 5);
    expect(half.agentKey, 'DK5');
    // a core refusing a history that goes backwards is a different agent
    expect(
        await checkTheRememberedAgent(
            localCoreOrigin: core,
            client: coreSaying({'verified': false, 'kind': 'different'})),
        TheRememberedAgent.somethingElseAnswers);
    // and what was kept does not move backwards
    await WhichHalfThisAppIsRunning.rememberTheProvedState(sequence: 2, key: 'DK2');
    expect((await WhichHalfThisAppIsRunning.now()).agentSequence, 5);
  });

  test('plain http to another host is refused when an agent is remembered',
      () async {
    SharedPreferences.setMockInitialValues({});
    await expectLater(
        WhichHalfThisAppIsRunning.pointAt(
            agentOrigin: 'http://203.0.113.9:5151', agentAid: 'EMINE'),
        throwsA(isA<Object>()));
    expect((await WhichHalfThisAppIsRunning.now()).isAController, isFalse);
  });
}
