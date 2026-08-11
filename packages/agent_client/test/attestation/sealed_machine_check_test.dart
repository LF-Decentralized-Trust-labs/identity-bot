import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:agent_client/attestation/attestation_verifier.dart';
import 'package:agent_client/attestation/sealed_machine_check.dart';
import 'package:agent_client/attestation/snp_report.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

/// The behaviour that decides what a person is told about the machine their
/// agent runs on.
///
/// The distinction under test throughout is between "checked and it holds",
/// "could not check", and "checked and it does not hold". Collapsing the first
/// two is the failure that matters: a caller reading a single boolean will
/// treat an unanswered question as a satisfied one.
void main() {
  Uint8List fixture(String name) => Uint8List.fromList(
      File('test/attestation/testdata/$name').readAsBytesSync());

  late Uint8List arkDer;
  late Uint8List askDer;

  setUpAll(() {
    arkDer = fixture('amd-ark-genoa.der');
    askDer = fixture('amd-ask-genoa.der');
  });

  SealedMachineCheck checkWith(String body, {int status = 200}) {
    return SealedMachineCheck(
      verifier: AttestationVerifier(
        trustedRootFingerprints: {AmdRoots.genoa},
        expectedMeasurements: {'00' * 48},
      ),
      client: MockClient((_) async => http.Response(body, status,
          headers: {'content-type': 'application/json'})),
    );
  }

  test('an agent on ordinary hardware is reported as such, not as a failure',
      () async {
    final s = await checkWith('{"backingType":"keychain_software"}')
        .check(baseUrl: 'http://agent', boundTo: 'x');
    expect(s.verdict, SealedMachineVerdict.notSealedHardware);
    expect(s.isProvenSealed, isFalse);
    // Someone running their own machine should not be told something is wrong.
    expect(s.explanation.toLowerCase(), contains('expected'));
  });

  test('an unreachable agent is unproven, never sealed', () async {
    final c = SealedMachineCheck(
      verifier: AttestationVerifier(
        trustedRootFingerprints: {AmdRoots.genoa},
        expectedMeasurements: {'00' * 48},
      ),
      client: MockClient((_) async => throw const SocketException('refused')),
    );
    final s = await c.check(baseUrl: 'http://agent', boundTo: 'x');
    expect(s.verdict, SealedMachineVerdict.unproven);
    expect(s.isProvenSealed, isFalse);
  });

  test('a claim of sealed hardware with no attestation proves nothing',
      () async {
    final s = await checkWith(jsonEncode({
      'sealedHardware': {
        'platform': 'sev-snp',
        'chain_note': 'could not produce one'
      }
    })).check(baseUrl: 'http://agent', boundTo: 'x');
    expect(s.verdict, SealedMachineVerdict.unproven);
    expect(s.isProvenSealed, isFalse);
  });

  // The case this whole exercise exists for: an agent that hands over a report
  // and no way to check it must not be believed.
  test('an attestation with no certificates is unproven, not sealed', () async {
    final report = Uint8List(SnpReport.reportSize);
    report.setRange(0x50, 0x50 + 64, bindReportData('x'));
    final s = await checkWith(jsonEncode({
      'sealedHardware': {
        'platform': 'sev-snp',
        'report': base64Encode(report),
      }
    })).check(baseUrl: 'http://agent', boundTo: 'x');
    expect(s.verdict, SealedMachineVerdict.unproven);
    expect(s.isProvenSealed, isFalse);
    expect(s.explanation, contains('not evidence'));
  });

  test('a report belonging to another machine is a failure, not a gap',
      () async {
    final report = Uint8List(SnpReport.reportSize);
    report.setRange(0x50, 0x50 + 64, bindReportData('somebody-else'));
    final s = await checkWith(jsonEncode({
      'sealedHardware': {
        'platform': 'sev-snp',
        'report': base64Encode(report),
        'certificate_chain': [base64Encode(askDer), base64Encode(arkDer)],
      }
    })).check(baseUrl: 'http://agent', boundTo: 'me');

    expect(s.verdict, SealedMachineVerdict.failed);
    expect(s.failure, AttestationFailure.notBoundToThisConnection);
    expect(s.isProvenSealed, isFalse);
    // Worth stopping for precisely because the attestation may be real.
    expect(s.explanation, contains('different machine'));
  });

  test('a chain that does not reach the pinned root fails', () async {
    final report = Uint8List(SnpReport.reportSize);
    report.setRange(0x50, 0x50 + 64, bindReportData('me'));
    final s = await checkWith(jsonEncode({
      'sealedHardware': {
        'platform': 'sev-snp',
        'report': base64Encode(report),
        // The intermediate alone: nothing here is a trusted root.
        'certificate_chain': [base64Encode(askDer)],
      }
    })).check(baseUrl: 'http://agent', boundTo: 'me');

    expect(s.verdict, SealedMachineVerdict.failed);
    expect(s.failure, AttestationFailure.chainBroken);
  });

  test('unreadable base64 is a failure and does not escape as an error',
      () async {
    final s = await checkWith(jsonEncode({
      'sealedHardware': {
        'platform': 'sev-snp',
        'report': 'not base64 !!!',
        'certificate_chain': ['also not base64 !!!'],
      }
    })).check(baseUrl: 'http://agent', boundTo: 'me');
    expect(s.verdict, SealedMachineVerdict.failed);
  });

  test('a malformed response yields a verdict rather than throwing', () async {
    for (final body in ['', 'not json', '[]', '{"sealedHardware": 7}']) {
      final s =
          await checkWith(body).check(baseUrl: 'http://agent', boundTo: 'x');
      expect(s.isProvenSealed, isFalse,
          reason: 'body ${jsonEncode(body)} was treated as proof');
    }
  });

  test('only a completed check reports as proven', () async {
    // Every verdict except sealed must read as not-proven, so a caller cannot
    // mistake an unanswered question for a satisfied one.
    for (final v in SealedMachineVerdict.values) {
      final s = SealedMachineStatus(verdict: v, explanation: '');
      expect(s.isProvenSealed, v == SealedMachineVerdict.sealed);
    }
  });
}
