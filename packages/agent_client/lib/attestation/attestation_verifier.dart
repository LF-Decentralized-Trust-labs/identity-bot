import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'snp_report.dart';
import 'x509.dart';

/// Why a report failed, so a caller can respond differently to each.
///
/// A single boolean would make an unreachable service and a forged report the
/// same event, and they call for opposite responses: one is a reason to wait,
/// the other is a reason to refuse and stay refused.
enum AttestationFailure {
  /// The report is not the right size or shape to read at all.
  malformed,

  /// The certificate chain does not lead to the pinned root.
  chainBroken,

  /// The chain is sound but the report was not signed by the key it names.
  signatureInvalid,

  /// Genuine, but not the software that was expected.
  measurementMismatch,

  /// Genuine, but produced for something other than what this client is
  /// talking to — so it may have been copied from elsewhere.
  notBoundToThisConnection,

  /// Genuine, expected software, and the guest was launched with debugging
  /// permitted, so its memory is readable by whoever runs it.
  debuggable,
}

class AttestationException implements Exception {
  AttestationException(this.failure, this.message);
  final AttestationFailure failure;
  final String message;
  @override
  String toString() => 'AttestationException(${failure.name}): $message';
}

/// Decides whether a report proves what it appears to prove.
///
/// The order of the checks below is deliberate. Cheap structural checks come
/// before expensive cryptography, and every check runs against values read from
/// the report itself rather than values supplied alongside it. Anything that
/// arrives next to the report — a claimed measurement, a claimed identity — is
/// input to be checked, never a fact to be trusted.
class AttestationVerifier {
  AttestationVerifier({
    required this.trustedRootFingerprints,
    required this.expectedMeasurements,
    this.allowDebuggableGuest = false,
  });

  /// SHA-384 over the DER of each acceptable root, lowercase hex.
  ///
  /// Pinned rather than resolved through a system trust store: the whole point
  /// is to check against one known issuer, and a trust store is an open set
  /// that changes without us.
  final Set<String> trustedRootFingerprints;

  /// The measurements this client will accept, lowercase hex.
  ///
  /// Plural because more than one build is legitimately in service at once
  /// during a rollout. Empty is refused rather than treated as "anything" — a
  /// verifier that accepts every measurement passes every forgery too.
  final Set<String> expectedMeasurements;

  /// Off by default. A debuggable guest can be read by whoever launched it, so
  /// accepting one silently would verify a machine that is sealed in name only.
  final bool allowDebuggableGuest;

  /// Verifies a report and the chain that vouches for it.
  ///
  /// [chain] runs from the certificate that signed the report up towards the
  /// root. It is supplied by the party being checked, which sounds wrong and is
  /// not: nothing in it is trusted until it leads to the pinned root, and
  /// having it delivered here rather than fetched from the issuer means this
  /// client never tells a third party which machine it is talking to.
  ///
  /// [boundTo] is what the report must have been produced for — in practice the
  /// fingerprint of the key on the connection this report arrived over, which
  /// is what stops a genuine report being replayed onto a different connection.
  void verify({
    required Uint8List reportBytes,
    required List<Uint8List> chain,
    required String boundTo,
    DateTime? at,
  }) {
    final now = at ?? DateTime.now().toUtc();
    if (expectedMeasurements.isEmpty) {
      throw AttestationException(
        AttestationFailure.measurementMismatch,
        'no expected measurement was configured, so every image would pass. '
        'That is not verification.',
      );
    }

    final SnpReport report;
    try {
      report = SnpReport(reportBytes);
    } on ArgumentError catch (e) {
      throw AttestationException(
          AttestationFailure.malformed, e.message.toString());
    }

    // Bound to this connection, before anything expensive. A report copied
    // from another instance is genuine in every other respect and fails here.
    if (!report.isBoundTo(boundTo)) {
      throw AttestationException(
        AttestationFailure.notBoundToThisConnection,
        'the report was not produced for this connection. It may be genuine and '
        'have been copied from somewhere else.',
      );
    }

    if (!expectedMeasurements.contains(_hex(report.measurement))) {
      throw AttestationException(
        AttestationFailure.measurementMismatch,
        'the machine is running software this client does not expect '
        '(measured ${_hex(report.measurement)}).',
      );
    }

    if (report.debugAllowed && !allowDebuggableGuest) {
      throw AttestationException(
        AttestationFailure.debuggable,
        'the guest was launched with debugging permitted, so whoever runs it can '
        'read its memory. The report is genuine; the machine is not sealed.',
      );
    }

    final leaf = _verifyChainToPinnedRoot(chain, now);

    final key = leaf.ecPublicKey;
    if (key == null) {
      throw AttestationException(
        AttestationFailure.chainBroken,
        'the certificate that should have signed this report does not hold an EC key',
      );
    }
    if (!reportSignatureIsValid(report, key)) {
      throw AttestationException(
        AttestationFailure.signatureInvalid,
        'the report is not signed by the key in its own certificate, so it was not '
        'produced by that processor.',
      );
    }
  }

  /// The most certificates a legitimate chain has, with room to spare. An
  /// unbounded list is work an unauthenticated party gets to ask for.
  static const int _maxChainLength = 10;

  /// Walks the supplied chain and returns the leaf, or throws.
  X509Certificate _verifyChainToPinnedRoot(List<Uint8List> chain, DateTime at) {
    if (chain.isEmpty) {
      throw AttestationException(
        AttestationFailure.chainBroken,
        'no certificates were supplied, so nothing vouches for the report',
      );
    }
    if (chain.length > _maxChainLength) {
      throw AttestationException(
        AttestationFailure.chainBroken,
        'the chain has ${chain.length} certificates; no legitimate chain is that long',
      );
    }

    final certs = <X509Certificate>[];
    for (var i = 0; i < chain.length; i++) {
      try {
        certs.add(X509Certificate.parse(chain[i]));
      } catch (e) {
        // Deliberately every throw, not just the expected type. These bytes are
        // attacker-supplied, and an unexpected exception escaping here would
        // leave the caller with no verdict at all rather than a refusal.
        throw AttestationException(
          AttestationFailure.chainBroken,
          'certificate $i could not be read: $e',
        );
      }
    }

    for (var i = 0; i < certs.length; i++) {
      if (!certs[i].isValidAt(at)) {
        throw AttestationException(
          AttestationFailure.chainBroken,
          '"${certs[i].subject}" is not valid at $at',
        );
      }
    }

    // Every certificate that signs another must be permitted to. Pinning the
    // root says nothing about this: without it, a certificate issued only to
    // identify a machine could be presented as an authority over others.
    for (var i = 1; i < certs.length; i++) {
      if (!certs[i].isCertificateAuthority || !certs[i].maySignCertificates) {
        throw AttestationException(
          AttestationFailure.chainBroken,
          '"${certs[i].subject}" is used here to vouch for another certificate '
          'but is not permitted to sign certificates',
        );
      }
    }

    // Each certificate must be signed by the next one up. Signature linkage
    // rather than name matching: a name says who a certificate claims to come
    // from, a signature shows it.
    for (var i = 0; i < certs.length - 1; i++) {
      if (!_signedBy(certs[i], certs[i + 1])) {
        throw AttestationException(
          AttestationFailure.chainBroken,
          '"${certs[i].subject}" is not signed by "${certs[i + 1].subject}"',
        );
      }
    }

    // The last must be a root we already trust, and must vouch for itself.
    // Checking the fingerprint alone would accept a self-signed certificate
    // whose signature is nonsense; checking only the self-signature would
    // accept any root at all.
    final root = certs.last;
    final fingerprint = _hex(SHA384Digest().process(root.der));
    if (!trustedRootFingerprints.contains(fingerprint)) {
      throw AttestationException(
        AttestationFailure.chainBroken,
        'the chain ends at "${root.subject}", which is not a root this client trusts',
      );
    }
    if (!root.isSelfIssued || !_signedBy(root, root)) {
      throw AttestationException(
        AttestationFailure.chainBroken,
        'the trusted root does not verify against itself',
      );
    }
    return certs.first;
  }

  static bool _signedBy(X509Certificate child, X509Certificate issuer) {
    try {
      return child.isSignedBy(issuer);
    } catch (_) {
      // Any refusal or failure is "did not verify". Nothing about
      // attacker-supplied bytes should reach the caller as an exception.
      return false;
    }
  }

  /// The report's own signature: ECDSA on P-384 over SHA-384.
  ///
  /// Public so it can be exercised directly against a real signed report. The
  /// full [verify] path checks cheaper things first and stops at the first
  /// failure, so a test driving it cannot reach this one without already
  /// knowing what the report was bound to.
  ///
  /// Note the asymmetry with the certificates above, which are RSASSA-PSS. The
  /// same verification involves two entirely different signature schemes, and
  /// the report's r and s are raw little-endian rather than the DER-encoded
  /// big-endian pair a certificate carries. Reading one the way you read the
  /// other fails in a way that looks like tampering.
  static bool reportSignatureIsValid(SnpReport report, ECPublicKey key) {
    final digest = SHA384Digest().process(report.signedBytes);
    final verifier = ECDSASigner(null, null)
      ..init(false, PublicKeyParameter<ECPublicKey>(key));
    try {
      return verifier.verifySignature(
        digest,
        ECSignature(report.signatureR, report.signatureS),
      );
    } catch (_) {
      return false;
    }
  }

  static String _hex(Uint8List b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
}

/// AMD's root for the processor family this software runs on.
///
/// A fingerprint rather than the certificate itself: it is the smallest thing
/// that pins the chain, and it cannot be misread. The certificate is supplied
/// at verification time and checked against this.
class AmdRoots {
  static const String genoa =
      'd1b7bcfe685d19e63ca792957371b619cee792db280c312e7a00433d506224d5'
      '953ad9d348d74b4e176fba1b6a616eac';
}
