import 'dart:convert';

import 'package:agent_client/services/local_core_keri_service.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

// The core can return verified:true for a credential whose revocation it could
// not check. The result carries revocation_status so a caller can tell that
// from "checked, not revoked"; the verdict itself is the core's and unchanged.
Future<dynamic> verifyWith(Map<String, dynamic> answer) {
  final service = LocalCoreKeriService(
    baseUrl: 'http://core.test',
    client: MockClient((_) async => http.Response(jsonEncode(answer), 200)),
  );
  return service.verifyCredential(acdcJson: 'AAAA');
}

void main() {
  test('"not checked" is not read as "not revoked"', () async {
    final r = await verifyWith({
      'verified': true,
      'checks': {'structure': true, 'not_revoked': null},
      'errors': [],
      'acdc_said': 'ESaid',
      'revocation_status': 'not checked: no registry state held',
    });
    expect(r.verified, isTrue); // the verdict rule is not this package's to change
    expect(r.revocationStatus, 'not checked: no registry state held');
    expect(r.revocationChecked, isFalse);
    expect(r.revoked, isFalse);
  });

  test('a credential read as live reports that it was checked', () async {
    final r = await verifyWith({
      'verified': true, 'checks': {}, 'errors': [], 'acdc_said': 'ESaid',
      'revocation_status': 'not_revoked',
    });
    expect(r.revocationChecked, isTrue);
  });

  test('a revoked credential carries the core\'s reason', () async {
    final r = await verifyWith({
      'verified': false, 'checks': {'not_revoked': false}, 'errors': ['x'], 'acdc_said': 'ESaid',
      'revocation_status': 'revoked',
      'revocation_reason': 'the credential has been revoked by its issuer',
    });
    expect(r.revoked, isTrue);
    expect(r.revocationChecked, isFalse);
    expect(r.revocationReason, 'the credential has been revoked by its issuer');
  });

  test('a core that says nothing about revocation is not read as having checked', () async {
    final r = await verifyWith({'verified': true, 'checks': {}, 'errors': [], 'acdc_said': 'ESaid'});
    expect(r.revocationStatus, isNull);
    expect(r.revocationChecked, isFalse);
  });
}
