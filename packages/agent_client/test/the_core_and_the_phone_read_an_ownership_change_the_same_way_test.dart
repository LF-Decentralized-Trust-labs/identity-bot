import 'dart:convert';
import 'dart:io';

import 'package:agent_client/services/the_ceremony_this_device_agreed_to.dart';
import 'package:test/test.dart';

import 'support/the_core.dart';

void main() {
  // The fixture is what the organisation's Identity Agent really answered for a hand-over
// of two devices (identity-agent-core/server, a test there keeps its fields
// matching), at each of its two rotations.
  test('the core\'s real terms and rotations are what the phone expects', () async {
    final km = await keyMathOf(await buildTheCore('zz-core'));
    final j = jsonDecode(File('test/fixtures/a_real_hand_over_terms.json').readAsStringSync()) as Map<String, dynamic>;
    for (final stage in ['rot1', 'rot2']) {
      final r = CeremonyReading('signing', CeremonyTerms.fromJson(Map<String, dynamic>.from(j['${stage}_terms'])));
      final terms = r.terms!;
      expect(terms.unexpectedShape, isNull, reason: stage);
      final raw = base64Decode(j['${stage}_event']['raw_b64'] as String);
      await terms.expectedFor(j['a_aid'] as String).requireIn(km, raw);
      await terms.expectedFor(j['c_aid'] as String).requireIn(km, raw);
    }
  });
}
