import 'package:agent_client/services/a_profile_to_connect_on.dart';
import 'dart:io';

import 'package:agent_client/services/core_service.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

/// Connecting to an agent elsewhere never lands on a profile that holds an
/// identity, on a phone as on a desktop.
void main() {
  test('a profile that holds an identity gets a new one begun first', () async {
    var begun = 0;
    final made = await makeRoomOnAProfile(
        holdsAnIdentity: () async => true, beginAProfile: () async => begun++);
    expect(made, isTrue);
    expect(begun, 1);
  });

  test('an empty profile is used as it is', () async {
    var begun = 0;
    final made = await makeRoomOnAProfile(
        holdsAnIdentity: () async => false, beginAProfile: () async => begun++);
    expect(made, isFalse);
    expect(begun, 0);
  });

  test('a profile that could not be begun is an error, not a carry-on',
      () async {
    await expectLater(
        makeRoomOnAProfile(
            holdsAnIdentity: () async => true,
            beginAProfile: () async => throw Exception('disk full')),
        throwsException);
  });

  test('not being able to tell whether a profile holds an identity is an '
      'error, never "none"', () async {
    final down = MockClient((_) async => throw const SocketException('refused'));
    CoreService core() => CoreService(baseUrl: 'http://127.0.0.1:5050', inner: down);
    await expectLater(theOpenProfileHoldsAnIdentity(makeCore: core), throwsA(anything));
    var begun = 0;
    await expectLater(
        makeRoomOnAProfile(
            holdsAnIdentity: () => theOpenProfileHoldsAnIdentity(makeCore: core),
            beginAProfile: () async => begun++),
        throwsA(anything));
    expect(begun, 0, reason: 'nothing may be connected on a guess');
  });

  test('a core that answers "no identity yet" is an empty profile', () async {
    final fresh = MockClient((_) async => http.Response('{"initialized": false}', 200));
    expect(
        await theOpenProfileHoldsAnIdentity(
            makeCore: () => CoreService(baseUrl: 'http://127.0.0.1:5050', inner: fresh)),
        isFalse);
  });
}
