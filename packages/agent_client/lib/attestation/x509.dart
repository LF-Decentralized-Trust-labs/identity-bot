import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';

/// Just enough X.509 to walk one certificate chain.
///
/// This is deliberately not a general certificate library, and it should not
/// grow into one. It reads the four things a chain walk needs — what was
/// signed, the signature, the algorithm, and the key — and refuses anything it
/// does not recognise instead of guessing. A parser that copes with everything
/// is a parser that accepts things it should not, which in this position is the
/// whole failure.
///
/// Nothing here validates names, dates, basic constraints or revocation. The
/// caller pins the root by fingerprint, so the chain is one known shape rather
/// than an open-ended search through a trust store.
class X509Certificate {
  X509Certificate._({
    required this.der,
    required this.tbsBytes,
    required this.signature,
    required this.signatureAlgorithm,
    required this.subject,
    required this.issuer,
    required this.rsaPublicKey,
    required this.ecPublicKey,
  });

  /// AMD signs every certificate in the chain with RSASSA-PSS.
  static const String oidRsaPss = '1.2.840.113549.1.1.10';
  static const String oidRsaEncryption = '1.2.840.113549.1.1.1';
  static const String oidEcPublicKey = '1.2.840.10045.2.1';

  /// SHA-384 digest length. AMD's certificates specify a salt this size.
  static const int _saltLength = 48;

  final Uint8List der;

  /// The exact encoded bytes the signature covers.
  ///
  /// Re-encoding the parsed structure instead would be the classic mistake: a
  /// signature covers the bytes that were signed, not a structure that means
  /// the same thing. Any difference in how a length or a string is encoded and
  /// every signature fails.
  final Uint8List tbsBytes;

  final Uint8List signature;
  final String signatureAlgorithm;
  final String subject;
  final String issuer;

  /// Exactly one of these is non-null.
  final RSAPublicKey? rsaPublicKey;
  final ECPublicKey? ecPublicKey;

  bool get isSelfIssued => subject == issuer;

  static X509Certificate parse(Uint8List der) {
    final top = ASN1Parser(der).nextObject();
    if (top is! ASN1Sequence || (top.elements?.length ?? 0) < 3) {
      throw const FormatException(
          'not a certificate: expected a SEQUENCE of three elements');
    }
    final tbs = top.elements![0];
    final algSeq = top.elements![1];
    final sigBits = top.elements![2];

    if (tbs is! ASN1Sequence) {
      throw const FormatException('certificate body is not a SEQUENCE');
    }
    if (sigBits is! ASN1BitString) {
      throw const FormatException('certificate signature is not a BIT STRING');
    }

    final tbsElements = tbs.elements ?? const <ASN1Object>[];
    // v3: [0] version, serial, algorithm, issuer, validity, subject, key, ...
    if (tbsElements.length < 7) {
      throw FormatException(
        'certificate body has ${tbsElements.length} fields; a v3 certificate has at '
        'least 7. Only v3 is handled, because that is what is actually issued.',
      );
    }

    final rsa = _rsaKeyOrNull(tbsElements[6]);
    final ec = rsa == null ? _ecKeyOrNull(tbsElements[6]) : null;
    if (rsa == null && ec == null) {
      throw const FormatException(
        'the certificate holds a key that is neither RSA nor an EC key on a curve '
        'this understands',
      );
    }

    return X509Certificate._(
      der: der,
      tbsBytes: Uint8List.fromList(tbs.encodedBytes!),
      signature: _bitStringContent(sigBits),
      signatureAlgorithm: _algorithmOid(algSeq),
      subject: _name(tbsElements[5]),
      issuer: _name(tbsElements[3]),
      rsaPublicKey: rsa,
      ecPublicKey: ec,
    );
  }

  /// True when [issuerCert] signed this certificate.
  ///
  /// Only RSASSA-PSS with SHA-384 is accepted, because that is what AMD issues
  /// and because quietly supporting more algorithms here means quietly
  /// accepting a certificate signed with a weaker one.
  bool isSignedBy(X509Certificate issuerCert) {
    if (signatureAlgorithm != oidRsaPss) {
      throw FormatException(
        'certificate "$subject" is signed with $signatureAlgorithm; only RSASSA-PSS '
        'is accepted here',
      );
    }
    final key = issuerCert.rsaPublicKey;
    if (key == null) {
      throw FormatException(
          'issuer "${issuerCert.subject}" does not hold an RSA key');
    }

    // SHA-384 for both the content digest and the mask, with a 48-byte salt.
    // These are not defaults: they are what the issued certificates specify,
    // and a mismatch rejects every genuine certificate.
    //
    // It must be ParametersWithSaltConfiguration and NOT ParametersWithSalt,
    // and the difference is silent and total. Supplying a salt marks it as
    // known, and verification then compares against the salt you supplied
    // instead of recovering the real one from the signature — so every genuine
    // signature fails and the symptom is identical to a forged one. Only the
    // configuration form, which supplies a length rather than bytes, recovers
    // the salt. The random source is required by the constructor and is never
    // consulted when verifying.
    final signer = PSSSigner(RSAEngine(), SHA384Digest(), SHA384Digest())
      ..init(
          false,
          ParametersWithSaltConfiguration(
            PublicKeyParameter<RSAPublicKey>(key),
            FortunaRandom(),
            _saltLength,
          ));
    try {
      return signer.verifySignature(tbsBytes, PSSSignature(signature));
    } catch (_) {
      // A malformed signature is a failed verification, not a crash: the input
      // is attacker-supplied by construction.
      return false;
    }
  }

  static Uint8List _bitStringContent(ASN1BitString bits) {
    // The first content octet counts unused trailing bits and is not part of
    // the value. Including it shifts every byte and nothing verifies.
    final v = bits.valueBytes!;
    return Uint8List.fromList(v.sublist(1));
  }

  static String _algorithmOid(ASN1Object alg) {
    if (alg is! ASN1Sequence || alg.elements == null || alg.elements!.isEmpty) {
      throw const FormatException('algorithm identifier is not a SEQUENCE');
    }
    final oid = alg.elements!.first;
    if (oid is! ASN1ObjectIdentifier) {
      throw const FormatException(
          'algorithm identifier does not begin with an OID');
    }
    return oid.objectIdentifierAsString!;
  }

  static RSAPublicKey? _rsaKeyOrNull(ASN1Object spki) {
    if (spki is! ASN1Sequence || (spki.elements?.length ?? 0) < 2) return null;
    if (_algorithmOid(spki.elements![0]) != oidRsaEncryption) return null;

    final bits = spki.elements![1];
    if (bits is! ASN1BitString) return null;
    final inner = ASN1Parser(_bitStringContent(bits)).nextObject();
    if (inner is! ASN1Sequence || (inner.elements?.length ?? 0) < 2)
      return null;

    final modulus = inner.elements![0];
    final exponent = inner.elements![1];
    if (modulus is! ASN1Integer || exponent is! ASN1Integer) return null;
    return RSAPublicKey(modulus.integer!, exponent.integer!);
  }

  static ECPublicKey? _ecKeyOrNull(ASN1Object spki) {
    if (spki is! ASN1Sequence || (spki.elements?.length ?? 0) < 2) return null;
    final alg = spki.elements![0];
    if (_algorithmOid(alg) != oidEcPublicKey) return null;

    final bits = spki.elements![1];
    if (bits is! ASN1BitString) return null;
    final point = _bitStringContent(bits);

    // Only the uncompressed form, which is what is issued. A compressed point
    // would need decompression, and silently mis-reading one yields a key that
    // rejects every genuine signature.
    if (point.isEmpty || point[0] != 0x04) return null;
    final curve = ECCurve_secp384r1();
    if (point.length != 1 + 96) return null;
    return ECPublicKey(curve.curve.decodePoint(point), curve);
  }

  /// A readable name, used to order the chain and to say which certificate
  /// failed. Only the common name is read; nothing here depends on it being
  /// unique or meaningful.
  static String _name(ASN1Object name) {
    const oidCommonName = '2.5.4.3';
    if (name is! ASN1Sequence) return '';
    for (final rdn in name.elements ?? const <ASN1Object>[]) {
      if (rdn is! ASN1Set) continue;
      for (final pair in rdn.elements ?? const <ASN1Object>[]) {
        if (pair is! ASN1Sequence || (pair.elements?.length ?? 0) < 2) continue;
        final oid = pair.elements![0];
        if (oid is ASN1ObjectIdentifier &&
            oid.objectIdentifierAsString == oidCommonName) {
          final value = pair.elements![1];
          return String.fromCharCodes(value.valueBytes ?? const <int>[]);
        }
      }
    }
    return '';
  }
}
