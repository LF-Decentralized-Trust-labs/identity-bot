import 'dart:convert';
import 'dart:typed_data';

import 'package:blake3_dart/blake3_dart.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

/// Proving you are the owner of an agent you are not sitting at.
///
/// An agent cannot tell who you are from the connection. On hardware you rent,
/// the owner is remote by definition, so "this request came from the machine
/// the agent runs on" is never true for the person who actually owns it. The
/// agent accepts a signature instead, and this is the client half of that.
///
/// The bytes signed here have to match `canonicalRequestString` in the agent
/// exactly. Two implementations of one construction in two languages, released
/// separately — so a golden vector pins them together. Without it, a difference
/// of one newline rejects every request and nothing says why.
class OwnerSignature {
  /// Version prefix of the canonical string. Changing it is a wire change.
  static const version = 'IA-REQ-V1';

  /// Header carrying the signature.
  static const sigHeader = 'X-IA-Owner-Sig';

  /// Header carrying the timestamp that was signed.
  static const timestampHeader = 'X-IA-Owner-Timestamp';

  /// Header naming which owner key signed, when the caller knows it.
  static const aidHeader = 'X-IA-Owner-AID';

  /// The exact text the owner signs: method, path, timestamp, and a digest of
  /// the body.
  ///
  /// Every part is load-bearing. Without the method and path a captured
  /// signature could be pointed at a different endpoint; without the body
  /// digest it could be reused with different contents; without the timestamp
  /// it would be valid forever.
  static String canonicalString({
    required String method,
    required String path,
    required String timestamp,
    required List<int> body,
  }) {
    return [
      version,
      method.toUpperCase(),
      path,
      timestamp,
      blake3QB64(body),
    ].join('\n');
  }

  /// Signs a request and returns the headers to send with it.
  ///
  /// The timestamp is generated here rather than taken from the caller,
  /// because it is part of what gets signed and a caller that produced a
  /// different one would sign something the agent never sees.
  static Map<String, String> headers({
    required String method,
    required String path,
    required List<int> body,
    required Uint8List ownerSeed,
    String? ownerAid,
    DateTime? now,
  }) {
    final timestamp = rfc3339Seconds(now ?? DateTime.now().toUtc());
    final message = canonicalString(
      method: method,
      path: path,
      timestamp: timestamp,
      body: body,
    );

    final privateKey = ed.newKeyFromSeed(ownerSeed);
    final signature =
        ed.sign(privateKey, Uint8List.fromList(utf8.encode(message)));

    return {
      sigHeader: sigQB64(Uint8List.fromList(signature)),
      timestampHeader: timestamp,
      if (ownerAid != null && ownerAid.isNotEmpty) aidHeader: ownerAid,
    };
  }

  /// RFC3339 in UTC at second precision. The agent parses exactly this shape,
  /// and Dart's own `toIso8601String` emits milliseconds, which would not
  /// round-trip.
  static String rfc3339Seconds(DateTime t) {
    final u = t.toUtc();
    String two(int n) => n.toString().padLeft(2, '0');
    return '${u.year.toString().padLeft(4, '0')}-${two(u.month)}-${two(u.day)}'
        'T${two(u.hour)}:${two(u.minute)}:${two(u.second)}Z';
  }

  /// CESR qb64 for a 32-byte Blake3 digest: derivation code `E`, with one pad
  /// byte prepended so the code lands on a base64 character boundary.
  static String blake3QB64(List<int> data) {
    final digest = blake3(Uint8List.fromList(data));
    final padded = Uint8List.fromList([0, ...digest]);
    final b64 = base64Url.encode(padded).replaceAll('=', '');
    return 'E${b64.substring(1)}';
  }

  /// CESR qb64 for a 64-byte Ed25519 signature: code `0B`, two pad bytes.
  static String sigQB64(Uint8List signature) {
    final padded = Uint8List.fromList([0, 0, ...signature]);
    final b64 = base64Url.encode(padded).replaceAll('=', '');
    return '0B${b64.substring(2)}';
  }
}
