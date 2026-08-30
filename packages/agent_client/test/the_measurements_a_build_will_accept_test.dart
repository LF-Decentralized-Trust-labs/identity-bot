import 'package:test/test.dart';
import 'package:agent_client/config/accepted_measurements.dart';

/// What a build says it will accept.
///
/// Nothing is compiled in for a plain test run, and the empty answer is the
/// important one: an app that accepted anything when nobody had said what to
/// accept would make every other check on a sealed machine decorative.
void main() {
  test('a build told nothing accepts nothing', () {
    expect(acceptedMeasurements(), isEmpty,
        reason: 'no policy must mean adopt nothing, never adopt anything');
  });
}
