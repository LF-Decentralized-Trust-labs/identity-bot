import 'dart:io';
import 'dart:typed_data';

import 'package:agent_client/attestation/attestation_verifier.dart';
import 'package:agent_client/attestation/snp_report.dart';
import 'package:agent_client/attestation/x509.dart';
import 'package:pointycastle/export.dart';
import 'package:test/test.dart';

/// Verifying against the certificates AMD actually publishes.
///
/// These are AMD's own root and intermediate for one processor family,
/// downloadable by anyone from AMD's key distribution service. They identify
/// the manufacturer, not any particular machine, so they belong in a test.
///
/// Signature verification is one of the few places where a wrong
/// implementation and a right one behave identically until the moment they
/// matter. A hand-written parser fed hand-written inputs proves only that the
/// two agree with each other, so everything below runs against bytes this
/// project did not produce.
void main() {
  Uint8List fixture(String name) {
    final f = File('test/attestation/testdata/$name');
    return Uint8List.fromList(f.readAsBytesSync());
  }

  late Uint8List arkDer;
  late Uint8List askDer;

  setUpAll(() {
    arkDer = fixture('amd-ark-genoa.der');
    askDer = fixture('amd-ask-genoa.der');
  });

  String hex(Uint8List b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

  group('reading a real certificate', () {
    test('the root parses and names itself', () {
      final ark = X509Certificate.parse(arkDer);
      expect(ark.subject, 'ARK-Genoa');
      expect(ark.issuer, 'ARK-Genoa');
      expect(ark.isSelfIssued, isTrue);
      expect(ark.signatureAlgorithm, X509Certificate.oidRsaPss);
      expect(ark.rsaPublicKey, isNotNull);
      // 4096-bit key, so the modulus is 512 bytes.
      expect(ark.rsaPublicKey!.modulus!.bitLength, 4096);
    });

    test('the intermediate names the root as its issuer', () {
      final ask = X509Certificate.parse(askDer);
      expect(ask.subject, 'SEV-Genoa');
      expect(ask.issuer, 'ARK-Genoa');
      expect(ask.isSelfIssued, isFalse);
    });
  });

  group('signature verification against certificates we did not produce', () {
    test('the root verifies against itself', () {
      final ark = X509Certificate.parse(arkDer);
      expect(ark.isSignedBy(ark), isTrue,
          reason: 'a self-signed root that does not verify against its own key '
              'means the parser, the PSS parameters, or the extracted body is wrong');
    });

    test('the intermediate verifies against the root', () {
      final ark = X509Certificate.parse(arkDer);
      final ask = X509Certificate.parse(askDer);
      expect(ask.isSignedBy(ark), isTrue);
    });

    // The check that proves the one above means something. If verification
    // returned true regardless, both tests would pass and neither would be
    // testing anything.
    test('the root does NOT verify against the intermediate', () {
      final ark = X509Certificate.parse(arkDer);
      final ask = X509Certificate.parse(askDer);
      expect(ark.isSignedBy(ask), isFalse);
    });

    /// A tampered certificate must be refused. Whether it is refused while
    /// being read or while its signature is checked is not the point and is not
    /// asserted — tightening the parser legitimately moves a rejection earlier,
    /// and a test that pins the mechanism would fail on an improvement.
    bool refused(Uint8List der, X509Certificate issuer) {
      try {
        return !X509Certificate.parse(der).isSignedBy(issuer);
      } catch (_) {
        return true;
      }
    }

    test('altering any byte of the body causes a refusal', () {
      final ark = X509Certificate.parse(arkDer);
      // Several positions across the body rather than one, so this cannot pass
      // by landing somewhere structurally inert.
      for (final at in [40, 80, 200, 400, 700]) {
        final tampered = Uint8List.fromList(askDer);
        tampered[at] ^= 0x01;
        expect(refused(tampered, ark), isTrue,
            reason: 'a certificate altered at byte $at was accepted');
      }
    });

    // Specifically the signature path: the body is untouched and still parses,
    // so the only thing that can reject this is the signature check itself.
    test('altering the signature alone is caught by the signature check', () {
      final ark = X509Certificate.parse(arkDer);
      final tampered = Uint8List.fromList(askDer);
      tampered[tampered.length - 20] ^= 0x01;
      final cert = X509Certificate.parse(tampered);
      expect(cert.isSignedBy(ark), isFalse);
    });
  });

  group('the chain walk', () {
    // The fingerprint the client pins, recomputed here from the certificate
    // itself. If AmdRoots.genoa were ever mistyped, this fails.
    test('the pinned fingerprint is the fingerprint of the real root', () {
      expect(hex(SHA384Digest().process(arkDer)), AmdRoots.genoa);
    });

    // The constraints the walk enforces, read off the real certificates.
    // Without this, a bug in extension parsing would reject every genuine
    // chain and nothing here would notice.
    test('the real certificates carry the constraints the walk requires', () {
      final ark = X509Certificate.parse(arkDer);
      final ask = X509Certificate.parse(askDer);

      expect(ask.isCertificateAuthority, isTrue);
      expect(ask.maySignCertificates, isTrue);
      expect(ark.isCertificateAuthority, isTrue);
      expect(ark.maySignCertificates, isTrue);

      // Self-issued is decided on encoded names, not common names.
      expect(ark.isSelfIssued, isTrue);
      expect(ask.isSelfIssued, isFalse);

      // Dates parse, and are not accidentally inverted.
      expect(ask.notBefore.isBefore(ask.notAfter), isTrue);
      expect(ask.isValidAt(DateTime.utc(2030, 1, 1)), isTrue);
      expect(ask.isValidAt(DateTime.utc(2000, 1, 1)), isFalse);
      expect(ask.isValidAt(DateTime.utc(2099, 1, 1)), isFalse);
    });

    /// Drives the real chain through the walk itself.
    ///
    /// The report is synthetic and correctly bound, so every check up to and
    /// including the chain walk runs for real. It then stops at the leaf's key
    /// — the intermediate holds an RSA key where a report needs an EC one —
    /// which is exactly the point: reaching that failure proves the walk
    /// accepted the certificates, their validity, and their authority to sign.
    test('the real chain passes the walk', () {
      final report = Uint8List(SnpReport.reportSize);
      report.setRange(0x50, 0x50 + 64, bindReportData('a-connection'));

      final v = AttestationVerifier(
        trustedRootFingerprints: {AmdRoots.genoa},
        expectedMeasurements: {'00' * 48}, // the zeroed synthetic measurement
      );

      expect(
        () => v.verify(
            reportBytes: report,
            chain: [askDer, arkDer],
            boundTo: 'a-connection',
            at: DateTime.utc(2030, 1, 1)),
        throwsA(predicate(
            (e) => e is AttestationException && e.message.contains('EC key'))),
        reason: 'the walk should have accepted the real chain and stopped only '
            'at the leaf key type; any other failure means a genuine chain is '
            'being rejected',
      );
    });

    test('a chain whose intermediate is not a CA is refused', () {
      // The root used where an intermediate is expected is fine, but a leaf
      // would not be. Here the ORDER is reversed so the root sits below the
      // intermediate, which breaks the signature linkage rather than the CA
      // flag — both must be refused.
      final report = Uint8List(SnpReport.reportSize);
      report.setRange(0x50, 0x50 + 64, bindReportData('c'));
      final v = AttestationVerifier(
        trustedRootFingerprints: {AmdRoots.genoa},
        expectedMeasurements: {'00' * 48},
      );
      expect(
        () => v.verify(
            reportBytes: report,
            chain: [arkDer, askDer],
            boundTo: 'c',
            at: DateTime.utc(2030, 1, 1)),
        throwsA(isA<AttestationException>()),
      );
    });

    test('an expired chain is refused', () {
      final report = Uint8List(SnpReport.reportSize);
      report.setRange(0x50, 0x50 + 64, bindReportData('d'));
      final v = AttestationVerifier(
        trustedRootFingerprints: {AmdRoots.genoa},
        expectedMeasurements: {'00' * 48},
      );
      expect(
        () => v.verify(
            reportBytes: report,
            chain: [askDer, arkDer],
            boundTo: 'd',
            at: DateTime.utc(2099, 1, 1)),
        throwsA(predicate((e) =>
            e is AttestationException && e.message.contains('not valid at'))),
      );
    });

    test('a chain longer than any legitimate one is refused', () {
      final report = Uint8List(SnpReport.reportSize);
      report.setRange(0x50, 0x50 + 64, bindReportData('e'));
      final v = AttestationVerifier(
        trustedRootFingerprints: {AmdRoots.genoa},
        expectedMeasurements: {'00' * 48},
      );
      expect(
        () => v.verify(
            reportBytes: report,
            chain: List.filled(11, arkDer),
            boundTo: 'e',
            at: DateTime.utc(2030, 1, 1)),
        throwsA(predicate((e) =>
            e is AttestationException &&
            e.message.contains('no legitimate chain is that long'))),
      );
    });

    test('a chain ending at an untrusted root is refused', () {
      final v = AttestationVerifier(
        trustedRootFingerprints: {'00' * 48},
        expectedMeasurements: {'aa' * 48},
      );
      expect(
        () => v.verify(
            reportBytes: Uint8List(1184),
            chain: [askDer, arkDer],
            boundTo: 'x'),
        throwsA(isA<AttestationException>()),
      );
    });

    test('a verifier with no expected measurement refuses everything', () {
      final v = AttestationVerifier(
        trustedRootFingerprints: {AmdRoots.genoa},
        expectedMeasurements: const {},
      );
      expect(
        () => v.verify(
            reportBytes: Uint8List(1184), chain: [arkDer], boundTo: 'x'),
        throwsA(predicate((e) =>
            e is AttestationException &&
            e.failure == AttestationFailure.measurementMismatch)),
      );
    });

    test('an empty chain is refused rather than treated as trivially valid',
        () {
      final v = AttestationVerifier(
        trustedRootFingerprints: {AmdRoots.genoa},
        expectedMeasurements: {'aa' * 48},
      );
      expect(
        () => v.verify(reportBytes: Uint8List(1184), chain: [], boundTo: 'x'),
        throwsA(isA<AttestationException>()),
      );
    });
  });

  // The remaining leg — the processor's own certificate, and the report it
  // signed — is exercised where such a report is available. It is not committed
  // here because it would tie this test to one particular processor and place
  // that processor's identifier in the repository.
  //
  //   SNP_FIXTURES=/path/to/dir dart test test/attestation/x509_chain_test.dart
  //
  // expecting vcek.der and report.bin in that directory.
  group('the full chain, when a real report is available', () {
    final dir = Platform.environment['SNP_FIXTURES'];

    test('a processor certificate verifies against AMD, and signed its report',
        () {
      if (dir == null) {
        markTestSkipped('set SNP_FIXTURES to run against a real report');
        return;
      }
      final vcek = Uint8List.fromList(File('$dir/vcek.der').readAsBytesSync());
      final report =
          Uint8List.fromList(File('$dir/report.bin').readAsBytesSync());

      final leaf = X509Certificate.parse(vcek);
      expect(leaf.ecPublicKey, isNotNull,
          reason: 'a processor certificate carries an EC key even though it is '
              'itself signed with RSA');
      expect(leaf.isSignedBy(X509Certificate.parse(askDer)), isTrue);

      // The whole point: a signature a real processor produced verifies.
      //
      // Driven directly rather than through verify(), because verify() checks
      // what the report was bound to first and stops there, and that value is
      // not recoverable from the report itself.
      expect(
        AttestationVerifier.reportSignatureIsValid(
            SnpReport(report), leaf.ecPublicKey!),
        isTrue,
        reason: 'a real report failed against the certificate issued for the '
            'processor that signed it — so the byte order of r and s, the '
            'digest, or the extent of the signed region is wrong',
      );
    });

    test('one altered byte in a real report breaks its signature', () {
      if (dir == null) {
        markTestSkipped('set SNP_FIXTURES to run against a real report');
        return;
      }
      final vcek = Uint8List.fromList(File('$dir/vcek.der').readAsBytesSync());
      final report =
          Uint8List.fromList(File('$dir/report.bin').readAsBytesSync());
      final key = X509Certificate.parse(vcek).ecPublicKey!;

      // The measurement: the field an attacker would change, and the one every
      // other check reads.
      final tampered = Uint8List.fromList(report);
      tampered[0x90] ^= 0x01;

      expect(
          AttestationVerifier.reportSignatureIsValid(SnpReport(tampered), key),
          isFalse,
          reason: 'if this passes, the signature is not being checked at all');
    });

    test('a real report is refused against a different key', () {
      if (dir == null) {
        markTestSkipped('set SNP_FIXTURES to run against a real report');
        return;
      }
      final report =
          Uint8List.fromList(File('$dir/report.bin').readAsBytesSync());
      final curve = ECCurve_secp384r1();
      final wrong = ECPublicKey(curve.G, curve);
      expect(
          AttestationVerifier.reportSignatureIsValid(SnpReport(report), wrong),
          isFalse);
    });
  });
}
