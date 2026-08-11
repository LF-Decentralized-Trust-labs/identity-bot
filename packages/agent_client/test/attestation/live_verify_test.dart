import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:agent_client/attestation/attestation_verifier.dart';
import 'package:test/test.dart';

/// The whole chain, against a response a real sealed machine actually served.
///
/// Everything else in this directory tests the parts. This tests that the parts
/// agree with a machine — that a guest's own answer, unedited, satisfies the
/// client that has to accept it. The two were written against the same
/// specification and could still have disagreed about anything.
///
/// Off unless pointed at a captured response, because it needs one and a
/// captured response names a particular machine:
///
///   SNP_LIVE_RESPONSE=/path/to/attestation.json dart test test/attestation/
void main() {
  final path = Platform.environment['SNP_LIVE_RESPONSE'];

  test('a live attestation from a real guest verifies end to end', () {
    if (path == null) {
      markTestSkipped(
          'set SNP_LIVE_RESPONSE to a captured /api/attestation response');
      return;
    }
    final d = jsonDecode(File(path).readAsStringSync()) as Map<String, dynamic>;

    final report = base64Decode(d['report'] as String);
    final chain = [
      for (final c in (d['certificate_chain'] as List))
        base64Decode(c as String),
    ];
    // What the machine says it bound to. Recomputed rather than trusted — if
    // this string were wrong, the binding check below fails.
    final boundTo =
        (d['bound_to'] as String).split('\n').last.replaceAll(')', '');

    final v = AttestationVerifier(
      trustedRootFingerprints: {AmdRoots.genoa},
      expectedMeasurements: {d['measurement'] as String},
    );

    // Throws on any failure: chain, measurement, binding, signature, debug.
    v.verify(reportBytes: report, chain: chain, boundTo: boundTo);

    // And the negative, so the pass above means something.
    expect(
      () =>
          v.verify(reportBytes: report, chain: chain, boundTo: 'someone-else'),
      throwsA(predicate((e) =>
          e is AttestationException &&
          e.failure == AttestationFailure.notBoundToThisConnection)),
    );

    final tampered = Uint8List.fromList(report);
    tampered[0x90] ^= 0x01;
    expect(
      () => v.verify(reportBytes: tampered, chain: chain, boundTo: boundTo),
      throwsA(isA<AttestationException>()),
    );

    printOnFailure(
        'VERIFIED: measurement ${(d['measurement'] as String).substring(0, 16)}…, '
        '${chain.length} certificates, bound to ${boundTo.substring(0, 12)}…');
  });
}
