import 'dart:convert';
import 'package:http/http.dart' as http;
import '../config/agent_config.dart';

/// Type-agnostic preview returned by the scan gate (`/api/scan/decode`). The scanner renders
/// this without knowing what the transaction is — Go decided that from the Ask's action `t`.
class ScanPreview {
  final int t;
  final String action;
  final String title;
  final String subtitle;
  final String counterparty;
  final List<ScanDetail> details;
  final List<String> tierOptions;
  final String defaultTier;
  final String warning;

  /// Digest of the exact Ask bytes this preview describes. Echoed back on
  /// execute so the agent can prove it is acting on the request the user
  /// approved — see bindConsent in the core.
  final String askDigest;

  ScanPreview({
    required this.t,
    required this.action,
    required this.title,
    required this.subtitle,
    required this.counterparty,
    required this.details,
    required this.tierOptions,
    required this.defaultTier,
    required this.warning,
    this.askDigest = '',
  });

  factory ScanPreview.fromJson(Map<String, dynamic> json) {
    return ScanPreview(
      t: json['t'] ?? 0,
      action: json['action'] ?? '',
      title: json['title'] ?? 'Request',
      subtitle: json['subtitle'] ?? '',
      counterparty: json['counterparty'] ?? '',
      details: ((json['details'] as List?) ?? [])
          .map((d) => ScanDetail(
                label: (d['label'] ?? '').toString(),
                value: (d['value'] ?? '').toString(),
              ))
          .toList(),
      tierOptions: ((json['tier_options'] as List?) ?? [])
          .map((e) => e.toString())
          .toList(),
      defaultTier: json['default_tier'] ?? '',
      warning: json['warning'] ?? '',
      askDigest: (json['ask_digest'] ?? '') as String,
    );
  }
}

class ScanDetail {
  final String label;
  final String value;
  ScanDetail({required this.label, required this.value});
}

/// Client for the dumb-router scan gate. The scanner forwards the raw scanned URL here; Go
/// decodes the Ask, dispatches by action `t`, and returns a generic preview / result. The
/// scanner contains zero per-transaction logic.
class ScanService {
  final String baseUrl;
  final http.Client _client;

  ScanService({String? baseUrl, http.Client? client})
      : baseUrl = baseUrl ?? AgentConfig.coreBaseUrl,
        _client = client ?? http.Client();

  Future<ScanPreview> decode(String url) async {
    final resp = await _client.post(
      Uri.parse('$baseUrl/api/scan/decode'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'url': url}),
    );
    if (resp.statusCode != 200) {
      throw Exception('scan decode failed: ${resp.statusCode} ${resp.body}');
    }
    return ScanPreview.fromJson(jsonDecode(resp.body));
  }

  Future<Map<String, dynamic>> execute(
    String url, {
    required bool approved,
    String? tier,
    // The askDigest from the preview the user approved. The core refuses to
    // execute without it, so consent is always bound to the exact request
    // that was shown.
    required String askDigest,
  }) async {
    final resp = await _client.post(
      Uri.parse('$baseUrl/api/scan/execute'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'url': url,
        'approved': approved,
        'ask_digest': askDigest,
        if (tier != null && tier.isNotEmpty) 'tier': tier,
      }),
    );
    if (resp.statusCode != 200) {
      throw Exception('scan execute failed: ${resp.statusCode} ${resp.body}');
    }
    return jsonDecode(resp.body) as Map<String, dynamic>;
  }

  void dispose() => _client.close();
}
