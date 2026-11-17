import 'dart:convert';
import 'dart:io';

import 'package:login_dart/app_checks.dart';
import 'package:test/test.dart';

/// Every case in login-web's test-vectors/ed25519-keys.json: a key that names no
/// single signer (not a point, not canonical, of small order) is refused as a
/// witness key (code B) and as a verification key (code D), as the core and
/// login-verify refuse it.
void main() {
  final v = jsonDecode(File('../login-web/test-vectors/ed25519-keys.json').readAsStringSync())
      as Map<String, Object?>;
  final cases = (v['cases'] as List).cast<Map<String, Object?>>();

  test('the shared cases are there', () => expect(cases.length, greaterThanOrEqualTo(10)));

  for (final c in cases) {
    for (final code in ['B', 'D']) {
      test('${c['name']}, as code $code', () {
        final got = decodeMatter(c[code.toLowerCase()], code, 32);
        expect(got != null, c['ok']);
      });
    }
  }

  test('the identity point is no witness key, so a signature of R = identity, s = 0 is not checked at all', () {
    final identity = cases.firstWhere((c) => c['name'] == 'the identity point');
    expect(decodeMatter(identity['b'], 'B', 32), isNull);
    expect(decodeVerkey(identity['d']), isNull);
  });
}
