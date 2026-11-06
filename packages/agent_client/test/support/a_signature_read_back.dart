import 'dart:convert';
import 'dart:typed_data';

/// The 64 raw bytes of an Ed25519 signature written in CESR with a two
/// character code: an indexed one, as keymath writes it ("AA" at place 0,
/// "BA" when it opens no prior commitment). For a test's stand-in core, which
/// must read what the app now sends.
Uint8List rawOfIndexedSignature(String qb64) {
  if (qb64.length != 88) {
    throw FormatException('not a signature with a two character code', qb64);
  }
  // Two characters of code leave two bytes of padding to drop.
  return base64Url.decode('AA${qb64.substring(2)}').sublist(2);
}
