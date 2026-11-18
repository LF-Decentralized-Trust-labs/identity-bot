import 'dart:typed_data';

import 'app_checks.dart';

/// The public key an Apple App Attest attestation object is for, read from its
/// authenticator data, as the 65-byte uncompressed P-256 point.
///
/// The device gives the key only as a key identifier, never its public point, and
/// the attested key is the one the sign-in names, so the point is read from the
/// attestation object `attestKey` returns: its `authData` carries the credential
/// public key as a COSE map. Only the shape needed is read; whether the
/// attestation is genuine is the Identity Agent's to decide (`VerifyAppleAppAttest`).
Uint8List appleAttestedPoint(Uint8List attestationObject) {
  const bad =
      TrustRefused('the device\'s attestation is not an App Attest object');
  final top = _Cbor(attestationObject).readAll();
  if (top is! Map) throw bad;
  final auth = top['authData'];
  if (auth is! Uint8List || auth.length < 55) throw bad;
  final idLen = (auth[53] << 8) | auth[54];
  if (auth.length < 55 + idLen) throw bad;
  final cose = _Cbor(Uint8List.sublistView(auth, 55 + idLen)).readAll();
  if (cose is! Map) throw bad;
  final x = cose[-2], y = cose[-3];
  if (cose[1] != 2 ||
      x is! Uint8List ||
      y is! Uint8List ||
      x.length != 32 ||
      y.length != 32) {
    throw bad;
  }
  return Uint8List.fromList([4, ...x, ...y]);
}

/// The few CBOR items an attestation object holds: maps, arrays, byte and text
/// strings and integers, shortest-length, nothing indefinite.
class _Cbor {
  final Uint8List b;
  int at = 0;
  _Cbor(this.b);

  Object readAll() {
    final v = _item(0);
    if (at != b.length) throw const FormatException('trailing bytes');
    return v;
  }

  int _u8() {
    if (at >= b.length) throw const FormatException('truncated');
    return b[at++];
  }

  Object _item(int depth) {
    if (depth > 8) throw const FormatException('too deep');
    final h = _u8();
    final major = h >> 5, info = h & 0x1f;
    int arg;
    if (info < 24) {
      arg = info;
    } else if (info <= 26) {
      final n = 1 << (info - 24);
      arg = 0;
      for (var i = 0; i < n; i++) {
        arg = (arg << 8) | _u8();
      }
    } else {
      throw const FormatException('unsupported length');
    }
    switch (major) {
      case 0:
        return arg;
      case 1:
        return -1 - arg;
      case 2:
      case 3:
        if (at + arg > b.length) throw const FormatException('truncated');
        final s = Uint8List.sublistView(b, at, at + arg);
        at += arg;
        return major == 2 ? Uint8List.fromList(s) : String.fromCharCodes(s);
      case 4:
        return [for (var i = 0; i < arg; i++) _item(depth + 1)];
      case 5:
        final m = <Object, Object>{};
        for (var i = 0; i < arg; i++) {
          final k = _item(depth + 1);
          m[k] = _item(depth + 1);
        }
        return m;
    }
    throw const FormatException('unsupported item');
  }
}
