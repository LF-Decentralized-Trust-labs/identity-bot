import 'package:flutter/foundation.dart' show debugPrint;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'hardware_key_wrapper.dart';

/// Persists the BIP39 mnemonic to platform secure storage.
///
/// Platform backing:
///   iOS / macOS  → Keychain
///   Android      → Android Keystore
///   Windows      → DPAPI (CredentialManager)
///   Linux        → libsecret / kwallet
///   Web          → localStorage (insecure; acceptable for localhost-only web build)
///
/// ADR-027: where a real hardware secure element is available (iOS/macOS
/// today — see [HardwareKeyWrapper]), the mnemonic is additionally wrapped
/// by a P-256 key generated inside it before being written here. That key
/// never leaves the enclave; only wrap/unwrap results cross into this
/// process. There is deliberately no per-use OS authentication requirement
/// on it — AuthProvider is the sole authorization gate for whether to
/// unwrap at all (ADR-027 Layer 2). AuthProvider does not exist in this
/// codebase yet, so this class currently unwraps unconditionally, same as
/// it always has for any other stored secret; wiring the AuthProvider gate
/// in front of [loadMnemonic] is tracked as follow-up work once that
/// interface exists — no other call path should be added in the meantime.
///
/// Platforms without a hardware wrapper (Android, Windows, Linux today)
/// fall back to storing the plaintext exactly as ADR-014 describes — this
/// is additive protection where available, not a new requirement.
///
/// The mnemonic is the single source of truth for all key derivation.
/// It must be saved immediately after inception and never stored anywhere else.
class SecureKeyStore {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    // Use the LEGACY macOS keychain, not the iOS-style data-protection keychain.
    // The data-protection keychain requires a keychain-access-groups entitlement
    // (provisioning-profile-backed) that a non-sandboxed Developer-ID app can't
    // carry — it fails onboarding with errSecMissingEntitlement (-34018), and
    // declaring the entitlement makes the app un-launchable. The legacy keychain
    // needs no entitlement for a non-sandboxed app.
    mOptions: MacOsOptions(useDataProtectionKeychain: false),
  );

  static const _mnemonicKey = 'agent_mnemonic';

  /// Marks a value as hardware-wrapped (ADR-027) vs. legacy plaintext
  /// (ADR-014). Safe: a real BIP39 mnemonic is space-separated words and
  /// never starts with this prefix.
  static const _wrappedPrefix = 'hw1:';

  static Future<void> saveMnemonic(List<String> words) async {
    final plaintext = words.join(' ');
    final wrapped = await HardwareKeyWrapper.wrap(plaintext);
    final toStore = wrapped != null ? '$_wrappedPrefix$wrapped' : plaintext;
    await _storage.write(key: _mnemonicKey, value: toStore);
  }

  static Future<List<String>?> loadMnemonic() async {
    final value = await _storage.read(key: _mnemonicKey);
    if (value == null || value.isEmpty) return null;

    if (value.startsWith(_wrappedPrefix)) {
      final payload = value.substring(_wrappedPrefix.length);
      final plaintext = await HardwareKeyWrapper.unwrap(payload);
      if (plaintext == null) {
        debugPrint('[SecureKeyStore] failed to unwrap stored mnemonic');
        return null;
      }
      return plaintext.split(' ');
    }

    // Legacy (ADR-014) plaintext — installs that predate the hardware wrap,
    // or platforms without a wrapper implementation.
    return value.split(' ');
  }

  static Future<bool> hasMnemonic() async {
    return await _storage.containsKey(key: _mnemonicKey);
  }

  static Future<void> clearMnemonic() async {
    await _storage.delete(key: _mnemonicKey);
  }
}
