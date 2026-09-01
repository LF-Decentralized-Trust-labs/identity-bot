import 'dart:convert';
import 'package:http/http.dart' as http;
import '../config/agent_config.dart';

class UpdateSettings {
  final String channel;
  final bool autoApplyCritical;
  final bool optOutWarningShown;

  UpdateSettings({
    required this.channel,
    required this.autoApplyCritical,
    this.optOutWarningShown = false,
  });

  factory UpdateSettings.fromJson(Map<String, dynamic> json) {
    return UpdateSettings(
      channel: json['channel'] ?? 'stable',
      autoApplyCritical: json['auto_apply_critical'] ?? true,
      optOutWarningShown: json['opt_out_warning_shown'] ?? false,
    );
  }

  Map<String, dynamic> toJson() => {
        'channel': channel,
        'auto_apply_critical': autoApplyCritical,
        'opt_out_warning_shown': optOutWarningShown,
      };
}

class AvailableUpdate {
  final String component;
  final String installed;
  final String available;
  final bool critical;
  final bool belowMinimum;
  final bool requiresConfirm;

  AvailableUpdate({
    required this.component,
    required this.installed,
    required this.available,
    required this.critical,
    required this.belowMinimum,
    required this.requiresConfirm,
  });

  factory AvailableUpdate.fromJson(Map<String, dynamic> json) {
    return AvailableUpdate(
      component: json['component'] ?? '',
      installed: json['installed'] ?? '',
      available: json['available'] ?? '',
      critical: json['critical'] ?? false,
      belowMinimum: json['below_minimum'] ?? false,
      requiresConfirm: json['requires_confirm'] ?? true,
    );
  }
}

class GenuinenessStatus {
  final String status;
  final String? runningSha256;
  final String? expectedSha256;
  final String? installedVersion;
  final String? message;

  GenuinenessStatus({
    required this.status,
    this.runningSha256,
    this.expectedSha256,
    this.installedVersion,
    this.message,
  });

  factory GenuinenessStatus.fromJson(Map<String, dynamic> json) {
    return GenuinenessStatus(
      status: json['status'] ?? 'unknown',
      runningSha256: json['running_sha256'],
      expectedSha256: json['expected_sha256'],
      installedVersion: json['installed_version'],
      message: json['message'],
    );
  }
}

class UpdateStatus {
  final Map<String, String> installed;
  final String? lastChecked;
  final List<AvailableUpdate> available;
  final UpdateSettings settings;
  final GenuinenessStatus genuineness;
  final bool manifestPresent;

  UpdateStatus({
    required this.installed,
    this.lastChecked,
    required this.available,
    required this.settings,
    required this.genuineness,
    required this.manifestPresent,
  });

  factory UpdateStatus.fromJson(Map<String, dynamic> json) {
    final installedRaw = json['installed'] as Map<String, dynamic>? ?? {};
    return UpdateStatus(
      installed: installedRaw.map((k, v) => MapEntry(k, v.toString())),
      lastChecked: json['last_checked'],
      available: (json['available'] as List<dynamic>? ?? [])
          .map((e) => AvailableUpdate.fromJson(e as Map<String, dynamic>))
          .toList(),
      settings: UpdateSettings.fromJson(json['settings'] ?? {}),
      genuineness: GenuinenessStatus.fromJson(json['genuineness'] ?? {}),
      manifestPresent: json['manifest_present'] ?? false,
    );
  }
}

class ApplyUpdateResult {
  final String component;
  final String version;
  final bool applied;
  final bool rolledBack;
  final String? message;

  ApplyUpdateResult({
    required this.component,
    required this.version,
    required this.applied,
    required this.rolledBack,
    this.message,
  });

  factory ApplyUpdateResult.fromJson(Map<String, dynamic> json) {
    return ApplyUpdateResult(
      component: json['component'] ?? '',
      version: json['version'] ?? '',
      applied: json['applied'] ?? false,
      rolledBack: json['rolled_back'] ?? false,
      message: json['message'],
    );
  }
}

class UpdateService {
  final String baseUrl;
  final http.Client _client;

  UpdateService({String? baseUrl, http.Client? client})
      // THIS COMPUTER, deliberately, and it is the exception rather than an
      // oversight. An update installs software HERE. Pointing it at the agent
      // in controller mode would have this installation report the version of a
      // machine it is only the front end for, and offer to update software it
      // does not run.
      : baseUrl = baseUrl ?? AgentConfig.coreBaseUrl,
        _client = client ?? http.Client();

  Future<UpdateStatus> getStatus() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/updates/status'));
    if (response.statusCode != 200) {
      throw Exception('Failed to load update status: ${response.statusCode}');
    }
    return UpdateStatus.fromJson(jsonDecode(response.body));
  }

  Future<UpdateSettings> getSettings() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/updates/settings'));
    if (response.statusCode != 200) {
      throw Exception('Failed to load update settings: ${response.statusCode}');
    }
    return UpdateSettings.fromJson(jsonDecode(response.body));
  }

  Future<UpdateSettings> updateSettings(UpdateSettings settings) async {
    final response = await _client.put(
      Uri.parse('$baseUrl/api/updates/settings'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(settings.toJson()),
    );
    if (response.statusCode != 200) {
      throw Exception('Failed to save update settings: ${response.statusCode}');
    }
    return UpdateSettings.fromJson(jsonDecode(response.body));
  }

  Future<void> checkNow() async {
    final response = await _client.post(Uri.parse('$baseUrl/api/updates/check'));
    if (response.statusCode != 200) {
      throw Exception('Check now failed: ${response.statusCode}');
    }
  }

  Future<ApplyUpdateResult> apply({
    required String component,
    String? version,
    bool userConfirmed = false,
  }) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/updates/apply'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'component': component,
        if (version != null) 'version': version,
        'user_confirmed': userConfirmed,
      }),
    );
    if (response.statusCode != 200) {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Apply failed: ${response.statusCode}');
    }
    return ApplyUpdateResult.fromJson(jsonDecode(response.body));
  }

  void dispose() => _client.close();
}