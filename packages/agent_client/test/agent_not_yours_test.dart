import 'package:agent_client/services/core_service.dart';
import 'package:test/test.dart';

void main() {
  // The distinction this type exists to make.
  //
  // An agent nobody has claimed answers 200 with initialized false, and the
  // right thing to show is "set this up". An agent that is not yours answers
  // 403, and the right thing to show is "this is waiting for the person it was
  // set up for". Both used to arrive as the same exception, so every caller
  // treated the second as the first and offered a button that then failed.
  test('a refusal is its own type, not a generic failure', () {
    const refused = AgentNotYoursException();
    expect(refused, isA<Exception>());
    // Catchable deliberately, rather than by a bare `catch (_)` that cannot
    // tell it from the backend being down.
    expect(() => throw refused, throwsA(isA<AgentNotYoursException>()));
  });

  test('it says something a person could be shown', () {
    // Not a status code and not a stack trace. Whatever puts this on a screen
    // should not have to write the sentence itself.
    final said = const AgentNotYoursException().toString();
    expect(said, isNot(contains('403')));
    expect(said, isNot(contains('Exception:')));
    expect(said.toLowerCase(), contains('set up for'));
  });
}
