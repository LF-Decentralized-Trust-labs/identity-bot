import 'package:shared_preferences/shared_preferences.dart';

enum AgentMode {
  createNew,
  connectExisting,
}

enum EntityType {
  individual,
  organization,
}

class PreferencesService {
  static const String _modeKey = 'agent_mode';
  static const String _entityTypeKey = 'entity_type';
  static const String _serverUrlKey = 'server_url';
  static const String _setupCompleteKey = 'setup_complete';

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

  static Future<void> clearAll() async {
    final prefs = await _prefs;
    await prefs.remove(_modeKey);
    await prefs.remove(_entityTypeKey);
    await prefs.remove(_serverUrlKey);
    await prefs.remove(_setupCompleteKey);
  }

  static String modeDisplayName(AgentMode mode) {
    switch (mode) {
      case AgentMode.createNew:
        return 'Primary (New Identity)';
      case AgentMode.connectExisting:
        return 'Connected Device';
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
