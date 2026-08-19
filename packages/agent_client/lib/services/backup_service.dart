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

/// One backup run, as the core recorded it.
class BackupRun {
  final String id;
  final String timestamp;
  final int sizeBytes;
  final String snapshotType;
  final bool success;
  final List<String> destinations;
  final String? error;

  /// This archive was reopened and its contents checked before it was kept.
  /// A run without it succeeded at making a file, which is a different claim.
  final bool verified;

  /// It reached somewhere losing this device does not reach.
  final bool offDevice;

  /// It restores on its own. An incremental one does not, however recent.
  final bool selfSufficient;

  BackupRun({
    required this.id,
    required this.timestamp,
    required this.sizeBytes,
    required this.snapshotType,
    required this.success,
    required this.destinations,
    this.error,
    this.verified = false,
    this.offDevice = false,
    this.selfSufficient = false,
  });

  factory BackupRun.fromJson(Map<String, dynamic> json) => BackupRun(
        id: json['id'] ?? '',
        timestamp: json['timestamp'] ?? '',
        sizeBytes: json['size_bytes'] ?? 0,
        snapshotType: json['snapshot_type'] ?? '',
        success: json['success'] ?? false,
        destinations: List<String>.from(json['destinations'] ?? const []),
        error: json['error'],
        verified: json['verified'] ?? false,
        offDevice: json['off_device'] ?? false,
        selfSufficient: json['self_sufficient'] ?? false,
      );
}

class BackupStatus {
  final bool enabled;
  final String? lastBackupAt;
  final String health;
  final List<BackupDestination> destinations;
  final String? redundancyWarning;
  final String? antiDeadlockWarning;
  final int consecutiveFailures;

  /// The most recent archive that was reopened and proven to open.
  ///
  /// Null means no archive has ever been proven to open — which is not the
  /// same as no archive existing, and is the more alarming of the two.
  final String? lastVerifiedAt;

  /// The most recent archive that reached somewhere the loss of this device
  /// does not reach. Null means every archive ever made is on the machine
  /// that made it, which is a copy rather than a backup.
  final String? lastOffDeviceAt;

  /// What is missing, in the core's own plain words, or null when nothing is.
  final String? protection;

  final List<BackupRun> history;

  BackupStatus({
    required this.enabled,
    this.lastBackupAt,
    required this.health,
    required this.destinations,
    this.redundancyWarning,
    this.antiDeadlockWarning,
    this.consecutiveFailures = 0,
    this.lastVerifiedAt,
    this.lastOffDeviceAt,
    this.protection,
    this.history = const [],
  });

  /// Whether anything at all has ever been backed up. Distinguishes "not set
  /// up" from "set up and failing", which look identical if you only read
  /// [health] and are the opposite of each other to act on.
  bool get everRan => (lastBackupAt ?? '').isNotEmpty;

  /// The one sentence this status is worth. Written here rather than in each
  /// screen so both apps say the same true thing, and so no screen can
  /// accidentally summarise a red status optimistically.
  String get plainSummary {
    if (!everRan) {
      return enabled
          ? 'Backup is on, and nothing has been written yet'
          : 'Not set up yet - no backup has been made';
    }
    if ((lastOffDeviceAt ?? '').isEmpty) {
      return 'Backed up, but only onto this device';
    }
    if ((lastVerifiedAt ?? '').isEmpty) {
      return 'Backed up off this device, never checked that it opens';
    }
    return 'Backed up, off this device, and checked that it opens';
  }

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
      lastVerifiedAt: json['last_verified_at'],
      lastOffDeviceAt: json['last_off_device_at'],
      protection: json['protection'],
      history: (json['history'] as List<dynamic>? ?? const [])
          .map((h) => BackupRun.fromJson(h as Map<String, dynamic>))
          .toList(),
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

  static Future<void> removeDestination(String id) async {
    final resp = await http.delete(Uri.parse('$_base/destinations/$id'));
    if (resp.statusCode != 200) {
      throw Exception('Could not remove that destination: ${resp.body}');
    }
  }

  /// Turns backup on, and starts the daily schedule.
  ///
  /// This is the switch nothing in either app could reach. Backup shipped
  /// `enabled: false` with no caller anywhere that set it true, so the whole
  /// subsystem was unreachable by design rather than by oversight — every
  /// other route worked and none of them would ever be called on a timer.
  ///
  /// Reads the config first and writes it back changed, rather than sending a
  /// fresh one: a blank config would silently drop the destinations somebody
  /// had already added.
  static Future<void> turnOn({bool daily = true}) async {
    final cfg = await getConfig();
    cfg.enabled = true;
    cfg.scheduleDaily = daily;
    await saveConfig(cfg);
  }

  static Future<void> turnOff() async {
    final cfg = await getConfig();
    cfg.enabled = false;
    await saveConfig(cfg);
  }

  /// Asks for a backup on the schedule's terms - debounced by five minutes.
  ///
  /// This is NOT "back up now"; [exportNow] is. The distinction matters on a
  /// button, because a person who taps something labelled "back up now" and is
  /// told "scheduled" will go and check, find nothing, and conclude it is
  /// broken.
  ///
  /// Throws [BackupImpossible] when the agent has no way to reach its own root
  /// seed. The core checks that before answering rather than reporting
  /// "scheduled" for a run that will skip quietly minutes later.
  static Future<void> requestScheduledRun() async {
    final resp = await http.post(Uri.parse('$_base/trigger'));
    if (resp.statusCode == 409) {
      throw BackupImpossible(_detailOf(resp.body));
    }
    if (resp.statusCode != 200) throw Exception('Trigger failed: ${resp.body}');
  }

  /// Fetches back what a destination is holding, for a restore.
  static Future<Map<String, dynamic>> pullFrom(String destId) async {
    final resp = await http.post(Uri.parse('$_base/pull/$destId'));
    if (resp.statusCode != 200) {
      throw Exception('Could not fetch from that destination: ${resp.body}');
    }
    return jsonDecode(resp.body) as Map<String, dynamic>;
  }

  /// What this machine is holding for other identities. See B5 and B6.
  static Future<List<dynamic>> whatThisMachineHoldsFor(String identityAid) async {
    final resp = await http.get(Uri.parse('$_base/receive/$identityAid'));
    if (resp.statusCode != 200) {
      throw Exception('Could not list what is held: ${resp.body}');
    }
    final body = jsonDecode(resp.body);
    if (body is List) return body;
    return (body as Map<String, dynamic>)['archives'] as List<dynamic>? ??
        const [];
  }

  /// Pulls the core's own sentence out of an error body, so the reason a
  /// person is shown is the one the core actually gave rather than a status
  /// code dressed up as an explanation.
  static String _detailOf(String body) {
    try {
      final m = jsonDecode(body) as Map<String, dynamic>;
      final detail = (m['detail'] ?? m['error'] ?? m['message'] ?? '') as String;
      if (detail.isNotEmpty) return detail;
    } catch (_) {
      // Not JSON. Fall through to the raw body, which is still better than
      // inventing a message.
    }
    return body;
  }
}

/// This agent cannot take a backup at all, and the core said why.
///
/// Distinct from a failure, because nothing was attempted and retrying changes
/// nothing. The usual cause is an agent with no route to its own root seed.
class BackupImpossible implements Exception {
  final String reason;
  BackupImpossible(this.reason);
  @override
  String toString() => reason;
}