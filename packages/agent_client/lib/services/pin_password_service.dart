import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/key_derivators/argon2_native_int_impl.dart';

/// Stores and verifies the user's PIN and password as **Argon2id** hashes.
///
/// A PIN/password is a *knowledge* authentication factor — one of several the
/// Identity Agent can present to its assurance provider (which aggregates
/// factors into a NIST IAL/AAL tier; see `identity_level_service.dart`). The
/// user proves to their *own* agent that they possess the factor; the plaintext
/// is never written to disk — only a one-way hash used to verify re-entry.
///
/// **Why Argon2id (not a plain SHA hash).** A PIN is low-entropy (a 4–6 digit
/// PIN is only 10^4–10^6 possibilities). A fast hash (SHA-256) would be brute-
/// forceable in milliseconds if the stored blob were ever dumped. Argon2id is a
/// slow, memory-hard KDF, so an offline guess costs real time + memory per try.
/// The per-credential salt (from a CSPRNG) additionally defeats rainbow tables.
///
/// Stored format is a self-describing PHC-style string
/// `$argon2id$v=19$m=<kib>,t=<iters>,p=<lanes>$<b64 salt>$<b64 hash>`, so the
/// cost parameters can be tuned later without invalidating existing hashes
/// (verify re-derives with the parameters embedded in each stored string).
///
/// Platform backing (via flutter_secure_storage):
///   iOS / macOS → Keychain (Secure-Enclave-backed)
///   Android     → Android Keystore (hardware-backed on modern devices)
///   Windows     → DPAPI · Linux → libsecret / kwallet
///
/// TODO (deferred to the assurance-provider / score work — do NOT expand here):
///   - Move this factor's storage into the Identity Agent's own encrypted data
///     store (alongside other private data) rather than a standalone secret, and
///     wrap the stored hash with the device's Secure Enclave key for defense in
///     depth (dump-resistance even if the OS keystore is compromised).
///   - Expose it through the generic factor API so the assurance provider reads
///     any enrolled factor uniformly, instead of screens calling this directly.
///   - Run the Argon2id derivation off the main isolate (compute) so unlock
///     never janks the UI at higher cost parameters.
class PinPasswordService {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  static const _pinHashKey = 'auth_pin_hash';
  static const _passwordHashKey = 'auth_password_hash';

  // Argon2id cost parameters (OWASP-recommended minimum for Argon2id).
  // Embedded in every stored hash, so these can be raised later without
  // breaking already-stored credentials.
  static const int _memoryKiB = 19456; // 19 MiB
  static const int _iterations = 2;
  static const int _lanes = 1;
  static const int _keyLen = 32;
  static const int _saltLen = 16;

  // ── Hashing ─────────────────────────────────────────────────────────────

  static Uint8List _randomSalt() {
    final rnd = Random.secure();
    return Uint8List.fromList(
      List<int>.generate(_saltLen, (_) => rnd.nextInt(256)),
    );
  }

  static Uint8List _argon2id(
    String value,
    Uint8List salt, {
    required int memoryKiB,
    required int iterations,
    required int lanes,
  }) {
    final params = Argon2Parameters(
      Argon2Parameters.ARGON2_id,
      salt,
      desiredKeyLength: _keyLen,
      iterations: iterations,
      memory: memoryKiB,
      lanes: lanes,
    );
    final gen = Argon2BytesGenerator()..init(params);
    final out = Uint8List(_keyLen);
    gen.deriveKey(Uint8List.fromList(utf8.encode(value)), 0, out, 0);
    return out;
  }

  /// Encode a fresh hash of [value] as a self-describing PHC-style string.
  static String _encode(String value) {
    final salt = _randomSalt();
    final hash = _argon2id(
      value,
      salt,
      memoryKiB: _memoryKiB,
      iterations: _iterations,
      lanes: _lanes,
    );
    return '\$argon2id\$v=19\$m=$_memoryKiB,t=$_iterations,p=$_lanes'
        '\$${base64.encode(salt)}\$${base64.encode(hash)}';
  }

  /// Verify [value] against a stored PHC-style string, re-deriving with the
  /// parameters embedded in it. Returns false for any malformed/legacy value
  /// (e.g. an old SHA-256 hash) — such a credential must be re-set.
  static bool _verifyEncoded(String value, String stored) {
    final parts = stored.split('\$'); // ['', 'argon2id', 'v=19', 'm=..,t=..,p=..', salt, hash]
    if (parts.length != 6 || parts[1] != 'argon2id') return false;
    final cost = <String, int>{};
    for (final kv in parts[3].split(',')) {
      final pair = kv.split('=');
      if (pair.length == 2) cost[pair[0]] = int.tryParse(pair[1]) ?? -1;
    }
    final m = cost['m'] ?? -1, t = cost['t'] ?? -1, p = cost['p'] ?? -1;
    if (m < 1 || t < 1 || p < 1) return false;
    final Uint8List salt, expected;
    try {
      salt = base64.decode(parts[4]);
      expected = base64.decode(parts[5]);
    } catch (_) {
      return false;
    }
    final got = _argon2id(value, salt, memoryKiB: m, iterations: t, lanes: p);
    return _constantTimeEquals(got, expected);
  }

  static bool _constantTimeEquals(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  // ── PIN ─────────────────────────────────────────────────────────────────

  static Future<bool> hasPin() => _storage.containsKey(key: _pinHashKey);

  static Future<void> setPin(String pin) =>
      _storage.write(key: _pinHashKey, value: _encode(pin));

  /// Returns true if [pin] matches the stored hash.
  static Future<bool> verifyPin(String pin) async {
    final stored = await _storage.read(key: _pinHashKey);
    if (stored == null) return false;
    return _verifyEncoded(pin, stored);
  }

  static Future<void> clearPin() => _storage.delete(key: _pinHashKey);

  // ── Password ──────────────────────────────────────────────────────────────

  static Future<bool> hasPassword() =>
      _storage.containsKey(key: _passwordHashKey);

  static Future<void> setPassword(String password) =>
      _storage.write(key: _passwordHashKey, value: _encode(password));

  /// Returns true if [password] matches the stored hash.
  static Future<bool> verifyPassword(String password) async {
    final stored = await _storage.read(key: _passwordHashKey);
    if (stored == null) return false;
    return _verifyEncoded(password, stored);
  }

  static Future<void> clearPassword() => _storage.delete(key: _passwordHashKey);

  // ── Combined ──────────────────────────────────────────────────────────────

  /// True if the user has set either a PIN or a password.
  static Future<bool> hasAnyCredential() async =>
      await hasPin() || await hasPassword();

  /// Verifies [value] against whichever credentials exist (PIN first, then password).
  static Future<bool> verifyAny(String value) async {
    if (await hasPin() && await verifyPin(value)) return true;
    if (await hasPassword() && await verifyPassword(value)) return true;
    return false;
  }

  /// Clears all stored credentials. Call only on identity reset.
  static Future<void> clearAll() async {
    await _storage.delete(key: _pinHashKey);
    await _storage.delete(key: _passwordHashKey);
  }
}
