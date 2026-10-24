import 'dart:convert';

import 'package:http/http.dart' as http;

/// The core refused to extend an identity's key log because it does not hold
/// the identity's key: the key is on another device, or in this app, which
/// signs an event only after the core has added it.
///
/// Its [reason] is the core's own words, said to the person as they are.
class KeyNotHeldByTheCore implements Exception {
  final String reason;
  const KeyNotHeldByTheCore(this.reason);

  @override
  String toString() => reason;
}

/// Throws what the core said when it refused [response]: [KeyNotHeldByTheCore]
/// with its reason where that is why, otherwise its error, or [fallback].
Never refusedByTheCore(http.Response response, String fallback) {
  Map<String, dynamic>? body;
  try {
    final decoded = jsonDecode(response.body);
    if (decoded is Map<String, dynamic>) body = decoded;
  } catch (_) {}
  if (response.statusCode == 409 && body?['error'] == 'key_not_held_here') {
    throw KeyNotHeldByTheCore(
        (body?['details'] as String?) ?? 'This identity\'s key is not held by this Identity Agent.');
  }
  throw Exception(body?['error'] ?? '$fallback: ${response.statusCode}');
}
