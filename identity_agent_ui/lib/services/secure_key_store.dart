import 'package:flutter/foundation.dart' show debugPrint;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'package:agent_client/services/profile_scope.dart';
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
      debugPrint('[SecureKeyStore] the phrase did not survive the copy — leaving the original');
      return false;
    }
    await _storage.delete(key: _legacyMnemonicKey);
    return true;
  }

  /// Marks a value as hardware-wrapped (ADR-027) vs. legacy plaintext
  /// (ADR-014). Safe: a real BIP39 mnemonic is space-separated words and
  /// never starts with this prefix.
  static const _wrappedPrefix = 'hw1:';

  static Future<void> saveMnemonic(List<String> words) async {
    final plaintext = words.join(' ');
    final wrapped = await HardwareKeyWrapper.wrap(plaintext);
    final toStore = wrapped != null ? '$_wrappedPrefix$wrapped' : plaintext;
    await _storage.write(key: await _scopedKey(), value: toStore);
  }

  static Future<List<String>?> loadMnemonic() async {
    final value = await _storage.read(key: await _scopedKey());
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
    return await _storage.containsKey(key: await _scopedKey());
  }

  static Future<void> clearMnemonic() async {
    await _storage.delete(key: await _scopedKey());
  }

  /// Forgets the words, once their owner has confirmed they are written down.
  ///
  /// The words and the seed are different things and are kept for different
  /// lengths of time. The SEED stays — every new pairwise contact key, login
  /// relationship, asset key and the credential vault derives from it, so a
  /// root device that discarded it could not form another relationship. The
  /// WORDS are only an encoding of that seed, and once they exist on paper the
  /// copy on the device is a second place to steal them from and nothing else.
  ///
  /// This is also what gives the reminder somewhere to stop. A prompt that ends
  /// when a checkbox is ticked measures whether somebody clicked; one that ends
  /// when the words are gone measures whether they actually wrote them down.
  ///
  /// Verifies the deletion rather than assuming it. A silent failure here would
  /// leave the words in place while the interface said they were gone, which is
  /// worse than not offering it — the owner would stop protecting something
  /// they believe no longer exists.
  static Future<bool> forgetWordsAfterRecording() async {
    await _storage.delete(key: await _scopedKey());
    final stillThere = await _storage.containsKey(key: await _scopedKey());
    if (stillThere) {
      debugPrint('[SecureKeyStore] the phrase is still stored after deletion');
      return false;
    }
    return true;
  }
}
