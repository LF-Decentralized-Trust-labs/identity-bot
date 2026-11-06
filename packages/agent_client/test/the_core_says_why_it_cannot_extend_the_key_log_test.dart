import 'dart:convert';

import 'package:agent_client/services/the_key_is_not_held_by_the_core.dart';
import 'package:test/test.dart';
import 'package:http/http.dart' as http;

// What the core answers where it does not hold the identity's key, as its
// writeKeyNotHeldHere writes it.
const reason = "This identity's key is not held by this Identity Agent: it is on your device or in your app. "
    "This Identity Agent doesn't make this event itself; the app that holds the key makes it, "
    'signing it before it is added.';

http.Response refused() => http.Response(jsonEncode({'error': 'key_not_held_here', 'details': reason}), 409);

void main() {
  test('the core\'s reason for refusing reaches the person, word for word', () async {
    // A core that refuses to add to the identity's key log, as it answers any
    // route that would.
    Object? thrown;
    try {
      refusedByTheCore(refused(), 'Credential issuance failed');
    } catch (e) {
      thrown = e;
    }
    expect(thrown, isA<KeyNotHeldByTheCore>());
    // What a screen shows is the exception as a string: the reason itself,
    // not a generic failure or a status code.
    expect(thrown.toString(), reason);
  });

  test('any other refusal still says what the core said', () {
    Object? thrown;
    try {
      refusedByTheCore(http.Response(jsonEncode({'error': 'something else'}), 500), 'Rotation failed');
    } catch (e) {
      thrown = e;
    }
    expect(thrown, isNot(isA<KeyNotHeldByTheCore>()));
    expect(thrown.toString(), contains('something else'));
  });
}
