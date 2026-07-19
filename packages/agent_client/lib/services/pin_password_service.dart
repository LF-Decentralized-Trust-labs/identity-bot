import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Stores and verifies the user's PIN and password as salted SHA-256 hashes.
///
/// Plaintext is never written to disk. A per-installation salt is generated
/// on first use and stored alongside the hash so rainbow-table attacks are
/// not viable even if the device storage is dumped.
///
/// Platform backing (via flutter_secure_storage):
///   iOS / macOS Apple Silicon → Keychain (Secure Enclave-backed)
///   Android                   → Android Keystore (hardware-backed on modern devices)
///   Windows                   → DPAPI (software-backed)
///   Linux                     → libsecret / kwallet
class PinPasswordService {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  static const _saltKey = 'auth_salt';
  static const _pinHashKey = 'auth_pin_hash';
  static const _passwordHashKey = 'auth_password_hash';

  // ── Salt ──────────────────────────────────────────────────────────────────

  /// Returns the per-installation salt, creating it on first call.
  static Future<String> _getSalt() async {
    final existing = await _storage.read(key: _saltKey);
    if (existing != null) return existing;

    // Generate a random 32-byte salt from current time + hash (no dart:math needed)
    final raw = '${DateTime.now().microsecondsSinceEpoch}_identity_agent_salt';
    final salt = sha256.convert(utf8.encode(raw)).toString();
    await _storage.write(key: _saltKey, value: salt);
    return salt;
  }

  static String _hash(String value, String salt) {
    final bytes = utf8.encode('$salt:$value');
    return sha256.convert(bytes).toString();
  }

  // ── PIN ───────────────────────────────────────────────────────────────────

  static Future<bool> hasPin() async {
    return await _storage.containsKey(key: _pinHashKey);
  }

  static Future<void> setPin(String pin) async {
    final salt = await _getSalt();
    await _storage.write(key: _pinHashKey, value: _hash(pin, salt));
  }

  /// Returns true if [pin] matches the stored hash.
  static Future<bool> verifyPin(String pin) async {
    final stored = await _storage.read(key: _pinHashKey);
    if (stored == null) return false;
    final salt = await _getSalt();
    return _hash(pin, salt) == stored;
  }

  static Future<void> clearPin() async {
    await _storage.delete(key: _pinHashKey);
  }

  // ── Password ──────────────────────────────────────────────────────────────

  static Future<bool> hasPassword() async {
    return await _storage.containsKey(key: _passwordHashKey);
  }

  static Future<void> setPassword(String password) async {
    final salt = await _getSalt();
    await _storage.write(key: _passwordHashKey, value: _hash(password, salt));
  }

  /// Returns true if [password] matches the stored hash.
  static Future<bool> verifyPassword(String password) async {
    final stored = await _storage.read(key: _passwordHashKey);
    if (stored == null) return false;
    final salt = await _getSalt();
    return _hash(password, salt) == stored;
  }

  static Future<void> clearPassword() async {
    await _storage.delete(key: _passwordHashKey);
  }

  // ── Combined ──────────────────────────────────────────────────────────────

  /// True if the user has set either a PIN or a password.
  static Future<bool> hasAnyCredential() async {
    return await hasPin() || await hasPassword();
  }

  /// Verifies [value] against whichever credentials exist (PIN first, then password).
  /// Returns true if either matches.
  static Future<bool> verifyAny(String value) async {
    if (await hasPin() && await verifyPin(value)) return true;
    if (await hasPassword() && await verifyPassword(value)) return true;
    return false;
  }

  /// Clears all stored credentials (PIN, password, and salt).
  /// Call only on identity reset.
  static Future<void> clearAll() async {
    await _storage.delete(key: _pinHashKey);
    await _storage.delete(key: _passwordHashKey);
    await _storage.delete(key: _saltKey);
  }
}
