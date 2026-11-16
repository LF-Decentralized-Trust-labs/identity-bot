import 'dart:convert';
import 'dart:io';

import 'package:login_dart/app_checks.dart';
import 'package:test/test.dart';

// The Dart link reader applies the rule for a utility app's back-end address
// that the Identity Agent core applies (identity-bot
// `identity-agent-core/backendaddr`) and the login page applies
// (`packages/login-web/src/app.ts`): every case in login-verify's
// back-end-addresses.json is decided alike. A front end has no build mode, so it
// accepts http on this machine, which the core accepts only in a development
// build. A change to the rule is made there, in the vectors, and in all three
// together, never in one alone.

// BACK_END_VECTORS names another file: the vectors of a core not yet pinned.
final cases = jsonDecode(File(Platform.environment['BACK_END_VECTORS'] ??
        '../login-verify/test-vectors/back-end-addresses.json')
    .readAsStringSync()) as Map<String, dynamic>;

void main() {
  test('every address is accepted or refused as the file says', () {
    final addresses = (cases['addresses'] as List).cast<Map<String, dynamic>>();
    expect(addresses.length, greaterThanOrEqualTo(40));
    for (final c in addresses) {
      expect(backEndAddress(c['address'] as String), c['accepted'],
          reason: '${c['name']} (${jsonEncode(c['address'])})');
    }
  });

  test('every link\'s api is read as the file says', () {
    final links = (cases['links'] as List).cast<Map<String, dynamic>>();
    expect(links.length, greaterThanOrEqualTo(8));
    for (final c in links) {
      expect(readLinkBackEnd(c['link_api'] as String), c['read_as'],
          reason: '${c['name']} (${jsonEncode(c['link_api'])})');
    }
  });

  test('an address over the bound is refused', () {
    expect(
        backEndAddress('https://tasks.example.com/${'a' * 2048}'), isFalse);
  });
}
