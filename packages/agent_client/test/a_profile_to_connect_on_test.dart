import 'package:agent_client/services/a_profile_to_connect_on.dart';
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
}
