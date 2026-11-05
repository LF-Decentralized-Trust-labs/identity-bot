import 'package:agent_client/services/finding_an_agent_that_moved.dart';
import 'package:agent_client/services/finding_it_again.dart';
import 'package:agent_client/services/which_half_this_app_is_running.dart';
import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

class _Finder implements FindingAnAgentThatMoved {
  _Finder(this.result);
  WhereTheAgentWent result;

  @override
  Future<WhereTheAgentWent> findAgain(
          {required WhichHalfThisAppIsRunning current,
          List<String> hints = const [],
          bool Function()? stillTheSameProfile}) async =>
      result;

  @override
  dynamic noSuchMethod(Invocation i) => null;
}

/// What the person is shown is decided here, once, for both apps: a wall only
/// when the agent is truly gone, and never "moved" unless a new address was
/// proven.
void main() {
  late ValueNotifier<WhereTheAgentWent?> outcome;

  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    await WhichHalfThisAppIsRunning.pointAt(
        agentOrigin: 'https://old.example.test', agentAid: 'EME');
    outcome = ValueNotifier(null);
  });

  FindingItAgain make({WhereTheAgentWent? finds}) => FindingItAgain(
        thing: 'identity',
        outcome: outcome,
        finder: _Finder(finds ?? const WhereTheAgentWent.notFound('x', [])),
        settle: () async => null,
      );

  test('nothing to say until startup has looked', () {
    expect(make().shows, WhatTheGateShows.theApp);
  });

  test('an agent that answers leaves the app untouched', () {
    outcome.value = const WhereTheAgentWent.stillThere('https://a.test');
    expect(make().shows, WhatTheGateShows.theApp);
  });

  test(
      'OFFLINE or machine off: a notice the person can ignore, never a wall, '
      'and never "moved"', () {
    outcome.value = const WhereTheAgentWent.unreachable('https://a.test',
        thing: 'identity');
    final it = make();
    expect(it.shows, WhatTheGateShows.anUnreachableNotice);
    expect(it.notice, isNot(contains('moved')));
    it.dismissNotice();
    expect(it.shows, WhatTheGateShows.theApp);
  });

  test(
      'truly gone: the question is asked, "not now" leaves a notice with the '
      'way back', () {
    outcome.value = const WhereTheAgentWent.notFound('https://a.test', [],
        thing: 'identity');
    final it = make();
    expect(it.shows, WhatTheGateShows.askingWhere);
    it.leaveItAlone();
    expect(it.shows, WhatTheGateShows.anUnreachableNotice);
    it.askAgain();
    expect(it.shows, WhatTheGateShows.askingWhere);
  });

  test(
      'a refused address is explained and changes nothing; a proven one is '
      'shown in words, without the scheme', () async {
    outcome.value = const WhereTheAgentWent.notFound('https://a.test', [],
        thing: 'identity');
    final it = make(
        finds: const WhereTheAgentWent.notFound('x', [
      'It is a different '
          'identity.'
    ]));
    await it.find('impostor.example.test');
    expect(it.shows, WhatTheGateShows.askingWhere);
    expect(it.message, 'It is a different identity.');

    final ok = make(
        finds: const WhereTheAgentWent.movedTo('https://box.example.test',
            from: 'https://a.test', thing: 'identity'));
    await ok.find('box.example.test');
    expect(ok.shows, WhatTheGateShows.found);
    ok.done();
    expect(ok.shows, WhatTheGateShows.theApp);
    expect(outcome.value, isNull);
  });

  test('an address nothing answers at says so in words', () async {
    outcome.value = const WhereTheAgentWent.notFound('https://a.test', [],
        thing: 'identity');
    final it = make(
        finds: const WhereTheAgentWent.unreachable('https://a.test',
            thing: 'identity'));
    await it.find('nowhere.example.test');
    expect(it.message, contains('online'));
    expect(it.message, isNot(contains('https://')));
  });
}
