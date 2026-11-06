import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'profile_scope.dart';

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

  /// The name the phrase used to be stored under, before profiles existed.
  static const _legacyMnemonicKey = 'agent_mnemonic';

  /// The name within a profile. Two identities on one installation would
  /// otherwise share a single slot, and the second would read the first's
  /// phrase — which is not a settings collision, it is one person's identity
  /// handed to another.
  static const _mnemonicName = 'mnemonic';

  static Future<String> _scopedKey() => ProfileScope.key(_mnemonicName);

  /// Moves a phrase written before profiles existed into the active profile.
  ///
  /// Copies, reads back, compares, and only then deletes the original. Never
  /// the other way round: this is the one value in the app where an
  /// interrupted migration means an identity nobody can recover, so it is
  /// written to be safe when it fails rather than only when it succeeds.
  ///
  /// Returns false if the phrase could not be moved, leaving the original
  /// exactly where it was.
  static Future<bool> migrateLegacyMnemonic() async {
    final scoped = await _scopedKey();
    if (await _storage.containsKey(key: scoped)) return true;

    final legacy = await _storage.read(key: _legacyMnemonicKey);
    if (legacy == null || legacy.isEmpty) return true;

    await _storage.write(key: scoped, value: legacy);
    if (await _storage.read(key: scoped) != legacy) {
      debugPrint(
          '[SecureKeyStore] the phrase did not survive the copy — leaving the original');
      return false;
    }
    await _storage.delete(key: _legacyMnemonicKey);
    return true;
  }

  static Future<void> saveMnemonic(List<String> words) async {
    await _storage.write(key: await _scopedKey(), value: words.join(' '));
  }

  static Future<List<String>?> loadMnemonic() async {
    final value = await _storage.read(key: await _scopedKey());
    if (value == null || value.isEmpty) return null;
    return value.split(' ');
  }

  static Future<bool> hasMnemonic() async {
    return await _storage.containsKey(key: await _scopedKey());
  }

  static Future<void> clearMnemonic() async {
    await _storage.delete(key: await _scopedKey());
  }

  /// The name within a profile of the phrase an identity is moving to, kept
  /// beside the phrase in force until the move is finished (ADR-061 section
  /// 10): between its two rotations both are needed, and losing either then
  /// loses the identity.
  static const _movingToName = 'mnemonic_moving_to';

  /// Keeps the phrase the identity is moving to, and reads it back: the move
  /// starts only once it is safely kept.
  static Future<bool> savePhraseMovingTo(List<String> words) async {
    final key = await ProfileScope.key(_movingToName);
    final value = words.join(' ');
    await _storage.write(key: key, value: value);
    return await _storage.read(key: key) == value;
  }

  /// The phrase the identity is moving to, or null when no move is under way.
  static Future<List<String>?> loadPhraseMovingTo() async {
    final value =
        await _storage.read(key: await ProfileScope.key(_movingToName));
    if (value == null || value.isEmpty) return null;
    return value.split(' ');
  }

  /// Drops a move that cannot happen, keeping the phrase in force.
  static Future<void> clearPhraseMovingTo() async {
    await _storage.delete(key: await ProfileScope.key(_movingToName));
  }

  /// Makes the phrase moved to the phrase in force, once the move's second
  /// rotation is in the log: written and read back first, and only then is
  /// the record of the move forgotten. Returns false, changing nothing it
  /// cannot confirm, when the new phrase did not survive the write.
  static Future<bool> finishMovingToThePhrase(List<String> words) async {
    final value = words.join(' ');
    final scoped = await _scopedKey();
    await _storage.write(key: scoped, value: value);
    if (await _storage.read(key: scoped) != value) return false;
    await _storage.delete(key: await ProfileScope.key(_movingToName));
    return true;
  }

  /// Forgets the words, once their owner has confirmed they are written down.
  ///
  /// The words and the seed are different things, kept for different lengths of
  /// time. The SEED stays — every new pairwise contact key, login relationship,
  /// asset key and the credential vault derives from it, so a root device that
  /// discarded it could not form another relationship. The WORDS are only an
  /// encoding of that seed, and once they are on paper the copy here is a
  /// second place to steal them from and nothing else.
  ///
  /// Verifies the deletion rather than assuming it. Reporting success while the
  /// words remain would be worse than not offering this at all: the owner would
  /// stop protecting something they believe no longer exists.
  static Future<bool> forgetWordsAfterRecording() async {
    await _storage.delete(key: await _scopedKey());
    return !(await _storage.containsKey(key: await _scopedKey()));
  }
}
