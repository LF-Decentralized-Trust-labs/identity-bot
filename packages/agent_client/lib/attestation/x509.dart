import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';

/// Raised when a certificate cannot be read, or reads as something this code
/// will not accept. Distinct from [FormatException] so a caller can tell a
/// refusal here from an unrelated parse failure elsewhere.
class CertificateException implements Exception {
  CertificateException(this.message);
  final String message;
  @override
  String toString() => 'CertificateException: $message';
}

/// Just enough X.509 to walk one certificate chain.
///
/// This is deliberately not a general certificate library and should not grow
/// into one. It reads what a chain walk needs and refuses anything it does not
/// recognise instead of guessing. A parser that copes with everything is a
/// parser that accepts things it should not, which in this position is the
/// whole failure.
///
/// The root is pinned by fingerprint, so the chain is one known shape rather
/// than a search through a trust store. That removes a great deal of X.509 —
/// no path building, no name constraints, no policy processing — but it does
/// NOT remove the structural checks below, because pinning the root says
/// nothing about what the certificates beneath it are permitted to do.
class X509Certificate {
  X509Certificate._({
    required this.der,
    required this.tbsBytes,
    required this.signature,
    required this.signatureAlgorithm,
    required this.subject,
    required this.issuer,
    required this.subjectDer,
    required this.issuerDer,
    required this.notBefore,
    required this.notAfter,
    required this.isCertificateAuthority,
    required this.maySignCertificates,
    required this.rsaPublicKey,
    required this.ecPublicKey,
  });

  static const String oidRsaPss = '1.2.840.113549.1.1.10';
  static const String oidRsaEncryption = '1.2.840.113549.1.1.1';
  static const String oidEcPublicKey = '1.2.840.10045.2.1';
  static const String _oidBasicConstraints = '2.5.29.19';
  static const String _oidKeyUsage = '2.5.29.15';

  /// SHA-384 digest length; the salt the issued certificates specify.
  static const int _saltLength = 48;

  final Uint8List der;

  /// The exact wire bytes the signature covers.
  ///
  /// Taken from the parser rather than re-encoded. Re-encoding would be the
  /// classic mistake: a signature covers the bytes that were signed, not a
  /// structure that means the same thing, and any difference in how a length
  /// or a string was encoded breaks every signature.
  ///
  /// Verified against pointycastle 4.0.0, whose parser builds each object from
  /// `Uint8List.view(bytes.buffer, offset, length)` — a view over the input,
  /// not a re-serialisation. If that library is upgraded, re-check it.
  final Uint8List tbsBytes;

  final Uint8List signature;
  final String signatureAlgorithm;

  /// Common names, for diagnostics only. Never compared to decide anything.
  final String subject;
  final String issuer;

  /// The encoded distinguished names. Comparisons use these, because two
  /// different names can share a common name.
  final Uint8List subjectDer;
  final Uint8List issuerDer;

  final DateTime notBefore;
  final DateTime notAfter;

  /// From basicConstraints. False when the extension is absent, which is what
  /// the specification means by its default.
  final bool isCertificateAuthority;

  /// From keyUsage's keyCertSign bit. True when keyUsage is absent, since an
  /// absent keyUsage constrains nothing.
  final bool maySignCertificates;

  /// Exactly one of these is non-null.
  final RSAPublicKey? rsaPublicKey;
  final ECPublicKey? ecPublicKey;

  /// Compared over encoded names, not common names.
  bool get isSelfIssued => _bytesEqual(subjectDer, issuerDer);

  bool isValidAt(DateTime t) => !t.isBefore(notBefore) && !t.isAfter(notAfter);

  static X509Certificate parse(Uint8List der) {
    // A certificate is DER, and DER has exactly one encoding of anything.
    //
    // Indefinite-length form is BER and forbidden in DER; the parser accepts
    // it. Refused at the outermost layer, where an attacker-chosen certificate
    // arrives. Nested encodings inside the body are covered differently and
    // more strongly: the signature is verified over the exact bytes, so any
    // re-encoding within the body changes what was signed and fails.
    if (der.length < 2)
      throw CertificateException('too short to be a certificate');
    if (der[1] == 0x80) {
      throw CertificateException(
          'the certificate uses indefinite-length encoding, which DER forbids');
    }

    final top = _need<ASN1Sequence>(
        _parseOne(der), 'a certificate is a SEQUENCE of three elements');

    // Trailing bytes after a complete certificate are not part of it, and
    // accepting them means two different inputs are treated as one certificate.
    final encodedLength = top.encodedBytes?.length ?? 0;
    if (encodedLength != der.length) {
      throw CertificateException(
        'the certificate is $encodedLength bytes but ${der.length} were supplied; '
        'trailing bytes are not part of it',
      );
    }
    final elements = top.elements ?? const <ASN1Object>[];
    if (elements.length < 3) {
      throw CertificateException(
          'a certificate has three elements; this has ${elements.length}');
    }

    final tbs = _need<ASN1Sequence>(elements[0], 'the certificate body');
    final outerAlg =
        _need<ASN1Sequence>(elements[1], 'the signature algorithm');
    final sigBits = _need<ASN1BitString>(elements[2], 'the signature');

    final tbsElements = tbs.elements ?? const <ASN1Object>[];
    // v3: [0] version, serial, algorithm, issuer, validity, subject, key, ...
    if (tbsElements.length < 7) {
      throw CertificateException(
        'the certificate body has ${tbsElements.length} fields; a v3 certificate '
        'has at least 7, and only v3 is accepted',
      );
    }

    // The algorithm is stated twice: once inside the signed body and once
    // outside it. Only the inner one is protected by the signature, so if they
    // disagree, the unsigned copy is describing the signature. Comparing the
    // encoded bytes closes that without needing to interpret the parameters.
    final innerAlg = _need<ASN1Sequence>(
        tbsElements[2], 'the signature algorithm inside the body');
    if (!_bytesEqual(_encoded(outerAlg), _encoded(innerAlg))) {
      throw CertificateException(
        'the certificate states one signature algorithm inside the signed body '
        'and a different one outside it, so the unsigned copy is describing the '
        'signature',
      );
    }

    final spki = tbsElements[6];
    final rsa = _rsaKeyOrNull(spki);
    final ec = rsa == null ? _ecKeyOrNull(spki) : null;
    if (rsa == null && ec == null) {
      throw CertificateException(
        'the certificate holds a key that is neither RSA nor an EC key on a '
        'curve this accepts',
      );
    }

    final validity = _need<ASN1Sequence>(tbsElements[4], 'the validity period');
    final validityElements = validity.elements ?? const <ASN1Object>[];
    if (validityElements.length < 2) {
      throw CertificateException('the validity period is missing a bound');
    }

    final extensions = _extensions(tbsElements);

    return X509Certificate._(
      der: der,
      tbsBytes: _encoded(tbs),
      signature: _bitStringContent(sigBits),
      signatureAlgorithm: _algorithmOid(outerAlg),
      subject: _commonName(tbsElements[5]),
      issuer: _commonName(tbsElements[3]),
      subjectDer: _encoded(tbsElements[5]),
      issuerDer: _encoded(tbsElements[3]),
      notBefore: _time(validityElements[0]),
      notAfter: _time(validityElements[1]),
      isCertificateAuthority: _basicConstraintsCa(extensions),
      maySignCertificates: _keyCertSign(extensions),
      rsaPublicKey: rsa,
      ecPublicKey: ec,
    );
  }

  /// True when [issuerCert] signed this certificate.
  ///
  /// Only RSASSA-PSS with SHA-384 is accepted, because that is what is issued
  /// and because quietly accepting more algorithms means quietly accepting a
  /// certificate signed with a weaker one.
  bool isSignedBy(X509Certificate issuerCert) {
    if (signatureAlgorithm != oidRsaPss) {
      throw CertificateException(
        'certificate "$subject" is signed with $signatureAlgorithm; only '
        'RSASSA-PSS is accepted',
      );
    }
    final key = issuerCert.rsaPublicKey;
    if (key == null) {
      throw CertificateException(
          'issuer "${issuerCert.subject}" does not hold an RSA key');
    }

    // SHA-384 for both the content digest and the mask, with a 48-byte salt.
    // These are stated by the certificates, not defaults.
    //
    // It must be ParametersWithSaltConfiguration and NOT ParametersWithSalt,
    // and the difference is silent and total. Supplying salt BYTES marks the
    // salt as known, and verification then compares against what was supplied
    // instead of recovering the real salt from the signature — so every genuine
    // signature fails and the symptom is identical to a forged one. Only the
    // configuration form, which takes a length, recovers it. The random source
    // is required by the constructor and is never consulted when verifying.
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
      // Any failure verifying attacker-supplied bytes is a failed verification,
      // never an error to propagate.
      return false;
    }
  }

  // ---- parsing helpers -----------------------------------------------------

  /// Every entry point runs on attacker-supplied bytes, so any throw from the
  /// ASN.1 library — not only [FormatException] — becomes a refusal.
  static ASN1Object _parseOne(Uint8List der) {
    if (der.isEmpty) throw CertificateException('empty certificate');
    try {
      return ASN1Parser(der).nextObject();
    } on CertificateException {
      rethrow;
    } catch (e) {
      throw CertificateException('could not be read as ASN.1: $e');
    }
  }

  static T _need<T extends ASN1Object>(ASN1Object o, String what) {
    if (o is! T) throw CertificateException('$what is not a $T');
    return o;
  }

  static Uint8List _encoded(ASN1Object o) {
    final b = o.encodedBytes;
    if (b == null) {
      throw CertificateException('an element carries no encoded bytes');
    }
    return Uint8List.fromList(b);
  }

  static Uint8List _bitStringContent(ASN1BitString bits) {
    final v = bits.valueBytes;
    if (v == null || v.isEmpty) {
      throw CertificateException('a BIT STRING has no content');
    }
    // The first content octet counts unused trailing bits. Everything read
    // here is a whole number of bytes, so anything but zero is malformed
    // rather than something to round away.
    if (v[0] != 0) {
      throw CertificateException(
          'a BIT STRING declares ${v[0]} unused bits where a whole number of '
          'bytes was expected');
    }
    return Uint8List.fromList(v.sublist(1));
  }

  static String _algorithmOid(ASN1Object alg) {
    final seq = _need<ASN1Sequence>(alg, 'an algorithm identifier');
    final elements = seq.elements ?? const <ASN1Object>[];
    if (elements.isEmpty) {
      throw CertificateException('an algorithm identifier is empty');
    }
    final oid =
        _need<ASN1ObjectIdentifier>(elements.first, 'an algorithm identifier');
    final s = oid.objectIdentifierAsString;
    if (s == null) {
      throw CertificateException('an algorithm identifier has no OID value');
    }
    return s;
  }

  static RSAPublicKey? _rsaKeyOrNull(ASN1Object spki) {
    if (spki is! ASN1Sequence || (spki.elements?.length ?? 0) < 2) return null;
    if (_algorithmOid(spki.elements![0]) != oidRsaEncryption) return null;

    final bits = spki.elements![1];
    if (bits is! ASN1BitString) return null;
    final inner = _parseOne(_bitStringContent(bits));
    if (inner is! ASN1Sequence || (inner.elements?.length ?? 0) < 2)
      return null;

    final modulus = inner.elements![0];
    final exponent = inner.elements![1];
    if (modulus is! ASN1Integer || exponent is! ASN1Integer) return null;
    final m = modulus.integer;
    final e = exponent.integer;
    if (m == null || e == null) return null;
    return RSAPublicKey(m, e);
  }

  static ECPublicKey? _ecKeyOrNull(ASN1Object spki) {
    if (spki is! ASN1Sequence || (spki.elements?.length ?? 0) < 2) return null;
    if (_algorithmOid(spki.elements![0]) != oidEcPublicKey) return null;

    final bits = spki.elements![1];
    if (bits is! ASN1BitString) return null;
    final point = _bitStringContent(bits);

    // Uncompressed form only, which is what is issued. Mis-reading a
    // compressed point yields a key that rejects every genuine signature.
    if (point.length != 1 + 96 || point[0] != 0x04) return null;
    final curve = ECCurve_secp384r1();
    try {
      return ECPublicKey(curve.curve.decodePoint(point), curve);
    } catch (_) {
      // A point that is not on the curve is not a key.
      return null;
    }
  }

  /// The extensions, keyed by OID. Absent for a certificate that has none.
  static Map<String, Uint8List> _extensions(List<ASN1Object> tbsElements) {
    final out = <String, Uint8List>{};
    for (var i = 7; i < tbsElements.length; i++) {
      final tagged = tbsElements[i];
      // Extensions are [3] EXPLICIT; anything else here is a field this code
      // does not need.
      if ((tagged.tag ?? 0) != 0xA3) continue;
      final value = tagged.valueBytes;
      if (value == null || value.isEmpty) continue;

      final seq = _parseOne(Uint8List.fromList(value));
      if (seq is! ASN1Sequence) continue;
      for (final ext in seq.elements ?? const <ASN1Object>[]) {
        if (ext is! ASN1Sequence) continue;
        final parts = ext.elements ?? const <ASN1Object>[];
        if (parts.length < 2) continue;
        // Decoded by position, not by "the last element".
        //
        // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
        //                          extnValue OCTET STRING }
        //
        // Taking the last element looks equivalent and is not: nothing stops a
        // crafted extension carrying further elements after extnValue, and the
        // reader would then take one of those as the value. Two or three
        // elements, in that order, or it is not an extension this will read.
        if (parts.length < 2 || parts.length > 3) continue;
        final oid = parts[0];
        if (oid is! ASN1ObjectIdentifier) continue;
        final name = oid.objectIdentifierAsString;
        if (name == null) continue;

        if (parts.length == 3 && parts[1] is! ASN1Boolean) continue;
        final value = parts[parts.length - 1];
        // extnValue is an OCTET STRING. Anything else here is not an encoding
        // ambiguity to work around, it is a different structure.
        if (value is! ASN1OctetString) continue;
        final payload = value.valueBytes;
        if (payload != null) out[name] = Uint8List.fromList(payload);
      }
    }
    return out;
  }

  /// BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE,
  ///                                  pathLenConstraint INTEGER OPTIONAL }
  ///
  /// Read by position. Taking "the first BOOLEAN found" is nearly equivalent
  /// and fails on exactly the input that matters: a crafted extension with a
  /// non-conforming first element and a BOOLEAN after it would have its cA read
  /// from a field that is not cA.
  static bool _basicConstraintsCa(Map<String, Uint8List> extensions) {
    final raw = extensions[_oidBasicConstraints];
    if (raw == null) return false; // absent means not a CA
    final seq = _parseOne(raw);
    if (seq is! ASN1Sequence) return false;
    final parts = seq.elements ?? const <ASN1Object>[];
    if (parts.isEmpty) return false; // cA defaults to FALSE
    final ca = parts.first;
    if (ca is! ASN1Boolean) return false; // cA omitted, so FALSE
    return ca.boolValue ?? false;
  }

  /// Whether keyUsage permits signing certificates.
  ///
  /// Absent means unconstrained, so true. But once the extension is PRESENT and
  /// cannot be read, the answer is false: something is asserting a restriction
  /// this code cannot evaluate, and the safe reading of an unreadable
  /// restriction is that it forbids.
  static bool _keyCertSign(Map<String, Uint8List> extensions) {
    final raw = extensions[_oidKeyUsage];
    if (raw == null) return true;
    final ASN1Object bits;
    try {
      bits = _parseOne(raw);
    } catch (_) {
      return false;
    }
    if (bits is! ASN1BitString) return false;

    final Uint8List content;
    try {
      // The same unused-bit validation every other BIT STRING gets. keyUsage
      // legitimately carries unused bits, so they are tolerated here — but the
      // count must still be a count, and the content must exist.
      final v = bits.valueBytes;
      if (v == null || v.isEmpty || v[0] > 7) return false;
      content = Uint8List.fromList(v.sublist(1));
    } catch (_) {
      return false;
    }

    // keyCertSign is bit 5, counting from the most significant bit of the
    // first content octet. An encoding too short to contain it does not assert
    // it.
    if (content.isEmpty) return false;
    return (content[0] & (1 << 2)) != 0;
  }

  static DateTime _time(ASN1Object o) {
    if (o is ASN1UtcTime && o.time != null) return o.time!.toUtc();
    if (o is ASN1GeneralizedTime && o.dateTimeValue != null) {
      return o.dateTimeValue!.toUtc();
    }
    throw CertificateException('a validity bound is not a time this can read');
  }

  /// The common name, for messages only.
  static String _commonName(ASN1Object name) {
    const oidCommonName = '2.5.4.3';
    if (name is! ASN1Sequence) return '';
    for (final rdn in name.elements ?? const <ASN1Object>[]) {
      if (rdn is! ASN1Set) continue;
      for (final pair in rdn.elements ?? const <ASN1Object>[]) {
        if (pair is! ASN1Sequence || (pair.elements?.length ?? 0) < 2) continue;
        final oid = pair.elements![0];
        if (oid is ASN1ObjectIdentifier &&
            oid.objectIdentifierAsString == oidCommonName) {
          return String.fromCharCodes(
              pair.elements![1].valueBytes ?? const <int>[]);
        }
      }
    }
    return '';
  }

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}
