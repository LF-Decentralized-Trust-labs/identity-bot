import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'attestation_verifier.dart';
import 'snp_report.dart';

/// What an agent is running on, as this client was able to establish it — not
/// as the agent described itself.
enum SealedMachineVerdict {
  /// Checked, and it is a sealed machine running software this client accepts.
  sealed,

  /// The agent reports no sealed hardware. Ordinary and correct for an agent
  /// on a laptop or a phone, where the user owns the machine and there is
  /// nobody to prove anything to.
  notSealedHardware,

  /// The agent claims sealed hardware but could not produce the certificates
  /// that make its report checkable. Nothing is proven either way.
  unproven,

  /// The agent claims sealed hardware and its evidence does not hold up.
  failed,
}

/// The result of asking an agent to prove what it runs on.
class SealedMachineStatus {
  const SealedMachineStatus({
    required this.verdict,
    required this.explanation,
    this.failure,
    this.measurement,
  });

  final SealedMachineVerdict verdict;

  /// Plain language, suitable to show a person. Says what was established
  /// rather than what the agent asserted.
  final String explanation;

  /// Set when the verdict is [SealedMachineVerdict.failed].
  final AttestationFailure? failure;

  /// The launch measurement that was verified, when one was.
  final String? measurement;

  /// True only where this client checked the evidence itself and it held.
  ///
  /// Deliberately not true for [SealedMachineVerdict.unproven]. "Could not
  /// check" and "checked and it passed" must never collapse into one boolean,
  /// because a caller reading a boolean will treat the first as the second.
  bool get isProvenSealed => verdict == SealedMachineVerdict.sealed;
}

/// Asks an agent to prove what machine it runs on, and checks the answer.
///
/// Until something on this side does this, connecting to a sealed machine and
/// connecting to an ordinary server are the same act: the agent describes
/// itself and the client believes it. Everything the hardware can prove is
/// wasted if the party that needs convincing never looks.
class SealedMachineCheck {
  SealedMachineCheck({
    required this.verifier,
    http.Client? client,
  }) : _client = client ?? http.Client();

  final AttestationVerifier verifier;
  final http.Client _client;

  /// Asks the agent at [baseUrl] what it runs on, and verifies the answer.
  ///
  /// [boundTo] is what the report must have been produced for. It has to be
  /// something this client already knows independently — the identifier it
  /// came here to talk to — because a value taken from the same response the
  /// report arrived in would be chosen by whoever wrote the report.
  Future<SealedMachineStatus> check({
    required String baseUrl,
    required String boundTo,
    Duration timeout = const Duration(seconds: 20),
  }) async {
    final Map<String, dynamic> body;
    try {
      final res = await _client
          .get(Uri.parse('$baseUrl/api/security/enclave'))
          .timeout(timeout);
      if (res.statusCode != 200) {
        return SealedMachineStatus(
          verdict: SealedMachineVerdict.unproven,
          explanation:
              'This agent did not answer when asked what it runs on (HTTP ${res.statusCode}), '
              'so nothing about its machine has been established.',
        );
      }
      body = jsonDecode(res.body) as Map<String, dynamic>;
    } catch (e) {
      return SealedMachineStatus(
        verdict: SealedMachineVerdict.unproven,
        explanation: 'This agent could not be asked what it runs on: $e',
      );
    }

    final sealedHardware = body['sealedHardware'];
    if (sealedHardware is! Map<String, dynamic>) {
      return const SealedMachineStatus(
        verdict: SealedMachineVerdict.notSealedHardware,
        explanation:
            'This agent runs on ordinary hardware rather than a sealed machine. That is '
            'expected where you own the machine yourself — there is nobody it needs to '
            'prove anything to.',
      );
    }

    final reportB64 = sealedHardware['report'];
    final chainB64 = sealedHardware['certificate_chain'];
    if (reportB64 is! String || reportB64.isEmpty) {
      return SealedMachineStatus(
        verdict: SealedMachineVerdict.unproven,
        explanation:
            'This agent says it runs on a sealed machine but produced no attestation to '
                    'show for it, so it cannot currently prove that. '
                    '${sealedHardware['chain_note'] ?? ''}'
                .trim(),
      );
    }
    if (chainB64 is! List || chainB64.isEmpty) {
      return SealedMachineStatus(
        verdict: SealedMachineVerdict.unproven,
        explanation:
            'This agent produced an attestation but not the certificates that vouch for '
            'it, so there is nothing to check it against. Its own account of itself is '
            'not evidence.',
      );
    }

    final Uint8List report;
    final List<Uint8List> chain;
    try {
      report = base64Decode(reportB64);
      chain = [
        for (final c in chainB64) base64Decode(c as String),
      ];
    } catch (e) {
      return SealedMachineStatus(
        verdict: SealedMachineVerdict.failed,
        failure: AttestationFailure.malformed,
        explanation:
            'This agent sent an attestation that could not be read: $e',
      );
    }

    try {
      verifier.verify(reportBytes: report, chain: chain, boundTo: boundTo);
    } on AttestationException catch (e) {
      return SealedMachineStatus(
        verdict: SealedMachineVerdict.failed,
        failure: e.failure,
        explanation: _plainly(e),
      );
    } catch (e) {
      // Nothing from verification may escape as an unhandled error. A caller
      // left without a verdict is worse off than one told it failed.
      return SealedMachineStatus(
        verdict: SealedMachineVerdict.failed,
        failure: AttestationFailure.malformed,
        explanation: 'This agent\'s attestation could not be checked: $e',
      );
    }

    final measurement = SnpReport(report)
        .measurement
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
    return SealedMachineStatus(
      verdict: SealedMachineVerdict.sealed,
      measurement: measurement,
      explanation:
          'Checked: this is a sealed machine running software you can rebuild yourself, '
          'and its operator cannot read what is inside it.',
    );
  }

  /// Turns a verification failure into something worth showing a person.
  ///
  /// Each of these means something different and calls for a different
  /// response, so they do not collapse into "attestation failed".
  static String _plainly(AttestationException e) {
    switch (e.failure) {
      case AttestationFailure.notBoundToThisConnection:
        return 'This agent presented an attestation belonging to a different machine. '
            'The attestation may itself be genuine, which is what makes this worth '
            'stopping for.';
      case AttestationFailure.measurementMismatch:
        return 'This machine is sealed but is running software this app does not '
            'recognise. That is not necessarily an attack — it may simply be a version '
            'this app has not been told about — but it cannot be verified.';
      case AttestationFailure.debuggable:
        return 'This machine was started in a way that lets whoever runs it read the '
            'memory inside. The attestation is genuine and the machine is not sealed.';
      case AttestationFailure.signatureInvalid:
        return 'This attestation is not signed by the processor it claims to come from.';
      case AttestationFailure.chainBroken:
        return 'This attestation does not lead back to a hardware manufacturer this app '
            'trusts: ${e.message}';
      case AttestationFailure.malformed:
        return 'This attestation could not be read: ${e.message}';
    }
  }
}
