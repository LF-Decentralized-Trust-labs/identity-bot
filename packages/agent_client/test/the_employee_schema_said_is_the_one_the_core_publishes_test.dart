import 'dart:convert';
import 'dart:io';

import 'package:agent_client/models/credential_schemas.dart';
import 'package:test/test.dart';

// Fails if the Dart constants drift from the vectors the core's own test
// checks against the schema file.
void main() {
  test('the constants equal the Employee Authorization vector', () {
    final file = File('../../identity-agent-core/schemas/credential-schema-vectors.json');
    final doc = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
    final entry = (doc['accepted'] as List)
        .cast<Map<String, dynamic>>()
        .firstWhere((e) => e['name'] == 'Employee Authorization');
    expect(kEmployeeAuthorizationSchemaSaid, entry['said']);
    expect(kEmployeeAuthorizationRetiredPlaceholderSaid,
        entry['retired_placeholder']);
    expect(kEmployeeAuthorizationSchemaSaids,
        {entry['said'], entry['retired_placeholder']});
  });
}
