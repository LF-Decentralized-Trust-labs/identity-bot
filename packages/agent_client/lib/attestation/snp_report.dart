import 'dart:typed_data';

import 'package:blake3_dart/blake3_dart.dart';

/// Reading an AMD SEV-SNP attestation report.
///
/// This is what lets a client decide, for itself, that it is talking to a
/// sealed machine rather than to an ordinary server that says it is one. Until
/// something on this side checks a report, "connect to your sealed box" and
/// "connect to a server" are the same code path, and every guarantee the
/// hardware provides stops at the host that produced it.
///
/// Parsing only. Signature and certificate checking live next to this, so that
/// the layout — which is fixed by AMD and easy to get quietly wrong — can be
/// tested on its own.
class SnpReport {
  SnpReport(this.raw) {
    if (raw.length < reportSize) {
      throw ArgumentError(
        'an SEV-SNP report is $reportSize bytes; got ${raw.length}. '
        'A short read here would otherwise be indistinguishable from a report '
        'whose fields happen to be zero.',
      );
    }
  }

  /// Field offsets, ABI 1.x. These are fixed by AMD, not by us.
  static const int reportSize = 1184;
  static const int _reportDataOffset = 0x50; // 64 bytes
  static const int _measurementStart = 0x90; // 48 bytes
  static const int _measurementEnd = 0xC0;
  static const int _policyOffset = 0x08; // 8 bytes
  static const int _tcbOffset = 0x180; // 8 bytes, little-endian
  static const int _chipIdOffset = 0x1A0; // 64 bytes
  static const int _signatureOffset = 0x2A0; // r then s

  /// Everything before the signature is what the signature covers.
  static const int signedLength = 0x2A0;

  /// r and s each occupy a fixed 72-byte field, whatever their actual length.
  static const int ecdsaComponentLength = 72;

  final Uint8List raw;

  /// What was launched. This is the value a client compares against the
  /// measurement published for the image it expects — and, because our builds
  /// are byte-reproducible, that anyone can derive from source themselves.
  Uint8List get measurement =>
      Uint8List.sublistView(raw, _measurementStart, _measurementEnd);

  /// The 64 bytes the guest chose when it asked for the report. This is the
  /// only field a client can bind anything of its own to.
  Uint8List get reportData =>
      Uint8List.sublistView(raw, _reportDataOffset, _reportDataOffset + 64);

  /// Identifies the CPU, not the instance. Many guests share one chip, so this
  /// says which machine answered and never which tenant.
  Uint8List get chipId =>
      Uint8List.sublistView(raw, _chipIdOffset, _chipIdOffset + 64);

  /// The firmware level the report was produced at. The certificate AMD issues
  /// is specific to it, so asking for the wrong one yields a certificate that
  /// will not verify — a failure that looks exactly like tampering.
  Uint8List get reportedTcb =>
      Uint8List.sublistView(raw, _tcbOffset, _tcbOffset + 8);

  int get _policy => ByteData.sublistView(raw, _policyOffset, _policyOffset + 8)
      .getUint64(0, Endian.little);

  /// Whether the host was permitted to attach a debugger to this guest.
  ///
  /// A report can be perfectly valid, chain to AMD, carry the expected
  /// measurement — and describe a guest the operator could read the memory of.
  /// Checking the signature and not this would verify a machine that is sealed
  /// in name only.
  bool get debugAllowed => (_policy & (1 << 19)) != 0;

  /// The bytes the signature covers.
  Uint8List get signedBytes => Uint8List.sublistView(raw, 0, signedLength);

  /// The signature, as two integers.
  ///
  /// THE TRAP: r and s are stored LITTLE-endian, and every bignum library reads
  /// big-endian. Feed the bytes in as they lie and you get two enormous wrong
  /// numbers, verification fails, and the symptom is identical to a forged
  /// report — nothing about it points at byte order. It is written down because
  /// it is easy to make and its symptom points nowhere near its cause.
  BigInt get signatureR => _bigIntFromLittleEndian(Uint8List.sublistView(
      raw, _signatureOffset, _signatureOffset + ecdsaComponentLength));

  BigInt get signatureS => _bigIntFromLittleEndian(Uint8List.sublistView(
      raw,
      _signatureOffset + ecdsaComponentLength,
      _signatureOffset + 2 * ecdsaComponentLength));

  static BigInt _bigIntFromLittleEndian(Uint8List le) {
    var out = BigInt.zero;
    for (var i = le.length - 1; i >= 0; i--) {
      out = (out << 8) | BigInt.from(le[i]);
    }
    return out;
  }

  /// True when this report was produced for [value] and not copied from some
  /// other instance.
  ///
  /// Compared in full, not by prefix: a report carrying the right first bytes
  /// and arbitrary remainder must not pass.
  bool isBoundTo(String value) {
    final want = bindReportData(value);
    final got = reportData;
    var diff = 0;
    for (var i = 0; i < want.length; i++) {
      diff |= want[i] ^ got[i];
    }
    return diff == 0;
  }
}

/// Recomputes what a guest puts in REPORT_DATA when it binds a report to a
/// value — an identifier, or the fingerprint of the TLS key it is serving.
///
/// This construction exists twice, here and in the host, and the two have to
/// agree byte for byte or every genuine report is rejected. Both sides are
/// pinned to the same golden vector in their tests, which is the only thing
/// that keeps them from drifting apart silently.
///
/// The domain separator and the trailing newline are part of the input. They
/// stop a value from being interpreted under some other scheme that hashes the
/// same bytes for a different purpose.
Uint8List bindReportData(String value) {
  final digest = blake3(Uint8List.fromList('IA-SNP-BIND-V1\n$value'.codeUnits));
  // REPORT_DATA is 64 bytes and blake3 gives 32. The remainder stays zero on
  // both sides; it is not padding to be filled with anything else later.
  final out = Uint8List(64);
  out.setRange(0, digest.length, digest);
  return out;
}
