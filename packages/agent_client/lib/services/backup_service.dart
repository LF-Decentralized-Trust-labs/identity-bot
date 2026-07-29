import 'dart:convert';
import 'package:http/http.dart' as http;
import '../config/agent_config.dart';

class BackupDestination {
  final String id;
  final String type;
  final String label;
  final String? localPath;
  final String? pairedUrl;
  final bool iaGated;
  final bool enabled;
  final String? lastSuccessAt;
  final String? lastError;

  BackupDestination({
    required this.id,
    required this.type,
    required this.label,
    this.localPath,
    this.pairedUrl,
    this.iaGated = false,
    this.enabled = true,
    this.lastSuccessAt,
    this.lastError,
  });

  factory BackupDestination.fromJson(Map<String, dynamic> json) {
    return BackupDestination(
      id: json['id'] ?? '',
      type: json['type'] ?? '',
      label: json['label'] ?? '',
      localPath: json['local_path'],
      pairedUrl: json['paired_url'],
      iaGated: json['ia_gated'] ?? false,
      enabled: json['enabled'] ?? true,
      lastSuccessAt: json['last_success_at'],
      lastError: json['last_error'],
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'type': type,
        'label': label,
        if (localPath != null) 'local_path': localPath,
        if (pairedUrl != null) 'paired_url': pairedUrl,
        'ia_gated': iaGated,
        'enabled': enabled,
      };
}

class BackupStatus {
  final bool enabled;
  final String? lastBackupAt;
  final String health;
  final List<BackupDestination> destinations;
  final String? redundancyWarning;
  final String? antiDeadlockWarning;
  final int consecutiveFailures;

  BackupStatus({
    required this.enabled,
    this.lastBackupAt,
    required this.health,
    required this.destinations,
    this.redundancyWarning,
    this.antiDeadlockWarning,
    this.consecutiveFailures = 0,
  });

  factory BackupStatus.fromJson(Map<String, dynamic> json) {
    return BackupStatus(
      enabled: json['enabled'] ?? false,
      lastBackupAt: json['last_backup_at'],
      health: json['health'] ?? 'red',
      destinations: (json['destinations'] as List<dynamic>? ?? [])
          .map((d) => BackupDestination.fromJson(d as Map<String, dynamic>))
          .toList(),
      redundancyWarning: json['redundancy_warning'],
      antiDeadlockWarning: json['anti_deadlock_warning'],
      consecutiveFailures: json['consecutive_failures'] ?? 0,
    );
  }
}

class BackupConfig {
  bool enabled;
  List<String> defaultTiers;
  List<BackupDestination> destinations;
  bool scheduleDaily;
  bool wifiOnlyTier23;
  String recoveryPreset;

  BackupConfig({
    this.enabled = false,
    this.defaultTiers = const ['tier1', 'tier2'],
    this.destinations = const [],
    this.scheduleDaily = true,
    this.wifiOnlyTier23 = true,
    this.recoveryPreset = 'seed',
  });

  factory BackupConfig.fromJson(Map<String, dynamic> json) {
    return BackupConfig(
      enabled: json['enabled'] ?? false,
      defaultTiers: List<String>.from(json['default_tiers'] ?? ['tier1', 'tier2']),
      destinations: (json['destinations'] as List<dynamic>? ?? [])
          .map((d) => BackupDestination.fromJson(d as Map<String, dynamic>))
          .toList(),
      scheduleDaily: json['schedule_daily'] ?? true,
      wifiOnlyTier23: json['wifi_only_tier23'] ?? true,
      recoveryPreset: json['recovery_preset'] ?? 'seed',
    );
  }

  Map<String, dynamic> toJson() => {
        'enabled': enabled,
        'default_tiers': defaultTiers,
        'destinations': destinations.map((d) => d.toJson()).toList(),
        'schedule_daily': scheduleDaily,
        'wifi_only_tier23': wifiOnlyTier23,
        'recovery_preset': recoveryPreset,
      };
}

class BackupService {
  static String get _base => '${AgentConfig.coreBaseUrl}/api/backup';

  static Future<BackupStatus> getStatus() async {
    final resp = await http.get(Uri.parse('$_base/status'));
    if (resp.statusCode != 200) {
      throw Exception('Backup status failed: ${resp.statusCode}');
    }
    return BackupStatus.fromJson(jsonDecode(resp.body) as Map<String, dynamic>);
  }

  static Future<BackupConfig> getConfig() async {
    final resp = await http.get(Uri.parse('$_base/config'));
    if (resp.statusCode != 200) throw Exception('Load config failed');
    return BackupConfig.fromJson(jsonDecode(resp.body) as Map<String, dynamic>);
  }

  static Future<void> saveConfig(BackupConfig config) async {
    final resp = await http.put(
      Uri.parse('$_base/config'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(config.toJson()),
    );
    if (resp.statusCode != 200) throw Exception('Save config failed');
  }

  /// Takes a backup.
  ///
  /// Deliberately does not send the recovery phrase, and no longer accepts one.
  /// A delegated device seals to the recovery public keys it was given at
  /// pairing; a root device reads its own wrapped seed off disk. Sending the
  /// words would put a second copy of the identity on the wire and derive the
  /// same key that would have been derived anyway.
  static Future<Map<String, dynamic>> exportNow({
    String? passphrase,
    List<String>? tiers,
    String? destPath,
  }) async {
    final resp = await http.post(
      Uri.parse('$_base/export'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        if (passphrase != null) 'passphrase': passphrase,
        if (tiers != null) 'tiers': tiers,
        if (destPath != null) 'dest_path': destPath,
      }),
    );
    if (resp.statusCode != 200) {
      final body = resp.body;
      throw Exception('Export failed: $body');
    }
    return jsonDecode(resp.body) as Map<String, dynamic>;
  }

  static Future<void> addDestination(BackupDestination dest) async {
    final resp = await http.post(
      Uri.parse('$_base/destinations'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'destination': dest.toJson()}),
    );
    if (resp.statusCode != 200) throw Exception('Add destination failed');
  }
}