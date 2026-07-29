import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Which identity this app's stored data belongs to.
///
/// Everything the client keeps — the recovery phrase, the server URL, whether
/// setup finished — used to live under a single flat name. That is fine while
/// there is one identity per installation and impossible the moment there are
/// two: the second would read the first's phrase and overwrite its settings.
/// Separate installations do not help, because these stores are keyed by app
/// identity rather than by process, so two copies of the same app share them.
///
/// So every key is scoped to a profile, and one unscoped key records which
/// profile is active. The interface may show only one for a long time; the
/// storage layout is what would be expensive to change later, because by then
/// there is real data under the old names on every installed device and the
/// migration must not lose a recovery phrase.
///
/// The identifier is a random string minted before onboarding, deliberately not
/// the AID: storage is written during setup, before an identity exists, and a
/// scheme that cannot name a profile until it has an AID cannot store the thing
/// that produces one.
class ProfileScope {
  /// The two keys that are never scoped — they are what tell us the scope.
  static const _activeProfileKey = 'active_profile_id';
  static const _knownProfilesKey = 'known_profile_ids';

  static String? _cached;

  static Future<SharedPreferences> get _prefs => SharedPreferences.getInstance();

  /// The active profile, creating one on first use.
  static Future<String> activeId() async {
    if (_cached != null) return _cached!;
    final prefs = await _prefs;
    var id = prefs.getString(_activeProfileKey);
    if (id == null || id.isEmpty) {
      id = _mintId();
      await prefs.setString(_activeProfileKey, id);
      await _register(prefs, id);
      debugPrint('[ProfileScope] created profile $id');
    }
    _cached = id;
    return id;
  }

  /// Scopes a storage key to the active profile.
  static Future<String> key(String name) async => 'profile.${await activeId()}.$name';

  /// Every profile this installation knows about.
  ///
  /// Kept as an explicit list rather than inferred from which keys happen to
  /// exist. Inference loses a profile that has been created but not yet written
  /// to — switch away from a fresh one and it would vanish, with no way back to
  /// it, which is the worst moment to disappear.
  static Future<List<String>> knownIds() async {
    final prefs = await _prefs;
    return (prefs.getStringList(_knownProfilesKey) ?? const <String>[]).toList()..sort();
  }

  /// Switches which profile subsequent reads and writes belong to.
  static Future<void> setActive(String id) async {
    final prefs = await _prefs;
    await prefs.setString(_activeProfileKey, id);
    await _register(prefs, id);
    _cached = id;
  }

  static Future<void> _register(SharedPreferences prefs, String id) async {
    final known = prefs.getStringList(_knownProfilesKey) ?? <String>[];
    if (known.contains(id)) return;
    await prefs.setStringList(_knownProfilesKey, [...known, id]);
  }

  /// Moves a value written under the old flat name into the active profile.
  ///
  /// Copies, reads back, compares, and only then removes the original. Never
  /// the other way round: on the mnemonic this is the difference between a
  /// migration and a lost identity, and a delete-then-write that is interrupted
  /// between the two leaves nothing at all.
  ///
  /// Returns false if anything did not line up, so a caller can leave the
  /// legacy value in place rather than pretend the move happened.
  static Future<bool> migrateValue({
    required String legacyName,
    required Future<String?> Function(String key) read,
    required Future<void> Function(String key, String value) write,
    required Future<void> Function(String key) remove,
  }) async {
    final scoped = await key(legacyName);

    // Already migrated, or written fresh under the new scheme. Do not touch a
    // legacy value in that case — it belongs to whatever wrote it.
    if (await read(scoped) != null) return true;

    final legacy = await read(legacyName);
    if (legacy == null) return true; // nothing to move

    await write(scoped, legacy);
    final verify = await read(scoped);
    if (verify != legacy) {
      debugPrint('[ProfileScope] $legacyName did not survive the copy — leaving the original');
      return false;
    }

    await remove(legacyName);
    debugPrint('[ProfileScope] migrated $legacyName into the active profile');
    return true;
  }

  /// A short random identifier. Not a UUID because nothing here needs global
  /// uniqueness — it only has to distinguish profiles inside one installation.
  static String _mintId() {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
    final rng = Random.secure();
    return List.generate(12, (_) => alphabet[rng.nextInt(alphabet.length)]).join();
  }

  @visibleForTesting
  static void resetCacheForTest() => _cached = null;
}
