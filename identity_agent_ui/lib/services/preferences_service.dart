import 'package:shared_preferences/shared_preferences.dart';

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

  static Future<AgentMode?> getMode() async {
    final prefs = await _prefs;
    final value = prefs.getString(_modeKey);
    if (value == null) return null;
    return AgentMode.values.firstWhere(
      (m) => m.name == value,
      orElse: () => AgentMode.createNew,
    );
  }

  static Future<void> setMode(AgentMode mode) async {
    final prefs = await _prefs;
    await prefs.setString(_modeKey, mode.name);
  }

  static Future<EntityType?> getEntityType() async {
    final prefs = await _prefs;
    final value = prefs.getString(_entityTypeKey);
    if (value == null) return null;
    return EntityType.values.firstWhere(
      (e) => e.name == value,
      orElse: () => EntityType.individual,
    );
  }

  static Future<void> setEntityType(EntityType type) async {
    final prefs = await _prefs;
    await prefs.setString(_entityTypeKey, type.name);
  }

  static Future<String?> getServerUrl() async {
    final prefs = await _prefs;
    return prefs.getString(_serverUrlKey);
  }

  static Future<void> setServerUrl(String url) async {
    final prefs = await _prefs;
    await prefs.setString(_serverUrlKey, url);
  }

  static Future<bool> isSetupComplete() async {
    final prefs = await _prefs;
    return prefs.getBool(_setupCompleteKey) ?? false;
  }

  static Future<void> setSetupComplete(bool complete) async {
    final prefs = await _prefs;
    await prefs.setBool(_setupCompleteKey, complete);
  }

  static Future<HostingChoice?> getHostingChoice() async {
    final prefs = await _prefs;
    final value = prefs.getString(_hostingChoiceKey);
    if (value == null) return null;
    return HostingChoice.values.firstWhere(
      (h) => h.name == value,
      orElse: () => HostingChoice.keysHereBrainHere,
    );
  }

  static Future<void> setHostingChoice(HostingChoice choice) async {
    final prefs = await _prefs;
    await prefs.setString(_hostingChoiceKey, choice.name);
  }

  static Future<String?> getRemoteBrainUrl() async {
    final prefs = await _prefs;
    return prefs.getString(_remoteBrainUrlKey);
  }

  static Future<void> setRemoteBrainUrl(String url) async {
    final prefs = await _prefs;
    await prefs.setString(_remoteBrainUrlKey, url);
  }

  static Future<bool> isScreenLockEnabled() async {
    final prefs = await _prefs;
    return prefs.getBool(_screenLockEnabledKey) ?? false;
  }

  static Future<void> setScreenLockEnabled(bool enabled) async {
    final prefs = await _prefs;
    await prefs.setBool(_screenLockEnabledKey, enabled);
  }

  static Future<void> clearAll() async {
    final prefs = await _prefs;
    await prefs.remove(_modeKey);
    await prefs.remove(_entityTypeKey);
    await prefs.remove(_serverUrlKey);
    await prefs.remove(_setupCompleteKey);
    await prefs.remove(_hostingChoiceKey);
    await prefs.remove(_remoteBrainUrlKey);
    await prefs.remove(_screenLockEnabledKey);
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
