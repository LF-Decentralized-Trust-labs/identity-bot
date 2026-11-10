import 'dart:convert';

import 'package:test/test.dart';
import 'package:agent_client/services/what_an_agent_calls_itself.dart';

/// What somebody is shown before an agent elsewhere is remembered: a name and
/// a picture. These are the cases that decide whether the name on that screen
/// is the one the agent actually holds.
void main() {
  test('an organisation is shown by its organisation name', () {
    final calls = WhatAnAgentCallsItself.fromProfileJson(
        jsonEncode({'fn': 'Pat Doe', 'org_name': 'America Ascent'}));
    expect(calls.name, 'America Ascent',
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
        jsonEncode({'org_name': 'America Ascent', 'photo': '%%%not base64'}));
    expect(calls.picture, isNull);
    expect(calls.name, 'America Ascent');
  });

  test('an agent that has been given nothing is shown as nothing, not as an error',
      () {
    final calls = WhatAnAgentCallsItself.fromProfileJson('{}');
    expect(calls.name, isEmpty);
    expect(calls.picture, isNull);
  });
}
