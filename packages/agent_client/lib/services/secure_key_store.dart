import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Persists the BIP39 mnemonic to platform secure storage.
///
/// Platform backing:
///   iOS / macOS  → Keychain
///   Android      → Android Keystore
///   Windows      → DPAPI (CredentialManager)
///   Linux        → libsecret / kwallet
///   Web          → localStorage (insecure; acceptable for localhost-only web build)
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
    mOptions: MacOsOptions(useDataProtectionKeyChain: false),
  );

  static const _mnemonicKey = 'agent_mnemonic';

  static Future<void> saveMnemonic(List<String> words) async {
    await _storage.write(key: _mnemonicKey, value: words.join(' '));
  }

  static Future<List<String>?> loadMnemonic() async {
    final value = await _storage.read(key: _mnemonicKey);
    if (value == null || value.isEmpty) return null;
    return value.split(' ');
  }

  static Future<bool> hasMnemonic() async {
    return await _storage.containsKey(key: _mnemonicKey);
  }

  static Future<void> clearMnemonic() async {
    await _storage.delete(key: _mnemonicKey);
  }
}
