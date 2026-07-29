import 'package:shared_preferences/shared_preferences.dart';

import 'profile_scope.dart';

enum AgentMode {
  createNew,
  connectExisting,
  backupOnly,
  recoverFromBackup,
}

enum EntityType {
  individual,
  organization,
}

enum HostingChoice {
  keysHereBrainHere,   // standalone — both keys and agent on this device
  keysHereBrainRemote, // keys here, agent brain on a remote server
  keysHereBrainLater,  // mobile-only: standalone now, connect remote brain later
}

class PreferencesService {
  static const String _modeKey = 'agent_mode';
  static const String _entityTypeKey = 'entity_type';
  static const String _serverUrlKey = 'server_url';
  static const String _setupCompleteKey = 'setup_complete';
  static const String _hostingChoiceKey = 'hosting_choice';
  static const String _remoteBrainUrlKey = 'remote_brain_url';
  static const String _screenLockEnabledKey = 'screen_lock_enabled';

  static Future<SharedPreferences> get _prefs => SharedPreferences.getInstance();

  /// Every stored value belongs to a profile.
  ///
  /// Resolved per call rather than cached in a field, because the active
  /// profile can change while the app is running and a stale scope would read
  /// one identity's settings into another's session.
  static Future<String> _k(String name) => ProfileScope.key(name);

  /// Moves values written before profiles existed into the active profile.
  ///
  /// Safe to call repeatedly: each value moves once, and anything already
  /// written under the new scheme is left alone.
  static Future<void> migrateLegacyKeys() async {
    final prefs = await _prefs;
    for (final name in _allKeys) {
      await ProfileScope.migrateValue(
        legacyName: name,
        read: (k) async => prefs.getString(k),
        write: (k, v) async => prefs.setString(k, v),
        remove: (k) async => prefs.remove(k),
      );
    }
  }

  static const List<String> _allKeys = [
    _modeKey,
    _entityTypeKey,
    _serverUrlKey,
    _setupCompleteKey,
    _hostingChoiceKey,
    _remoteBrainUrlKey,
    _screenLockEnabledKey,
  ];

  static Future<AgentMode?> getMode() async {
    final prefs = await _prefs;
    final value = prefs.getString(await _k(_modeKey));
    if (value == null) return null;
    return AgentMode.values.firstWhere(
      (m) => m.name == value,
      orElse: () => AgentMode.createNew,
    );
  }

  static Future<void> setMode(AgentMode mode) async {
    final prefs = await _prefs;
    await prefs.setString(await _k(_modeKey), mode.name);
  }

  static Future<EntityType?> getEntityType() async {
    final prefs = await _prefs;
    final value = prefs.getString(await _k(_entityTypeKey));
    if (value == null) return null;
    return EntityType.values.firstWhere(
      (e) => e.name == value,
      orElse: () => EntityType.individual,
    );
  }

  static Future<void> setEntityType(EntityType type) async {
    final prefs = await _prefs;
    await prefs.setString(await _k(_entityTypeKey), type.name);
  }

  static Future<String?> getServerUrl() async {
    final prefs = await _prefs;
    return prefs.getString(await _k(_serverUrlKey));
  }

  static Future<void> setServerUrl(String url) async {
    final prefs = await _prefs;
    await prefs.setString(await _k(_serverUrlKey), url);
  }

  static Future<bool> isSetupComplete() async {
    final prefs = await _prefs;
    return prefs.getBool(await _k(_setupCompleteKey)) ?? false;
  }

  static Future<void> setSetupComplete(bool complete) async {
    final prefs = await _prefs;
    await prefs.setBool(await _k(_setupCompleteKey), complete);
  }

  static Future<HostingChoice?> getHostingChoice() async {
    final prefs = await _prefs;
    final value = prefs.getString(await _k(_hostingChoiceKey));
    if (value == null) return null;
    return HostingChoice.values.firstWhere(
      (h) => h.name == value,
      orElse: () => HostingChoice.keysHereBrainHere,
    );
  }

  static Future<void> setHostingChoice(HostingChoice choice) async {
    final prefs = await _prefs;
    await prefs.setString(await _k(_hostingChoiceKey), choice.name);
  }

  static Future<String?> getRemoteBrainUrl() async {
    final prefs = await _prefs;
    return prefs.getString(await _k(_remoteBrainUrlKey));
  }

  static Future<void> setRemoteBrainUrl(String url) async {
    final prefs = await _prefs;
    await prefs.setString(await _k(_remoteBrainUrlKey), url);
  }

  static Future<bool> isScreenLockEnabled() async {
    final prefs = await _prefs;
    return prefs.getBool(await _k(_screenLockEnabledKey)) ?? false;
  }

  static Future<void> setScreenLockEnabled(bool enabled) async {
    final prefs = await _prefs;
    await prefs.setBool(await _k(_screenLockEnabledKey), enabled);
  }

  static Future<void> clearAll() async {
    final prefs = await _prefs;
    await prefs.remove(await _k(_modeKey));
    await prefs.remove(await _k(_entityTypeKey));
    await prefs.remove(await _k(_serverUrlKey));
    await prefs.remove(await _k(_setupCompleteKey));
    await prefs.remove(await _k(_hostingChoiceKey));
    await prefs.remove(await _k(_remoteBrainUrlKey));
    await prefs.remove(await _k(_screenLockEnabledKey));
  }

  static String modeDisplayName(AgentMode mode) {
    switch (mode) {
      case AgentMode.createNew:
        return 'Primary (New Identity)';
      case AgentMode.connectExisting:
        return 'Connected Device';
      case AgentMode.backupOnly:
        return 'Backup Only';
      case AgentMode.recoverFromBackup:
        return 'Recover from Backup';
    }
  }

  static String entityTypeDisplayName(EntityType type) {
    switch (type) {
      case EntityType.individual:
        return 'Individual';
      case EntityType.organization:
        return 'Organization';
    }
  }
}
