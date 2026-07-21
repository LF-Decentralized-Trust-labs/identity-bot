import 'dart:convert';
import 'package:http/http.dart' as http;
import '../config/agent_config.dart';

class LoginPreview {
  final String sessionToken;
  final String rpSessionUrl;
  final String siteAid;
  final String siteOobi;
  final String audience;
  final List<String> requestedDisclosures;
  final Map<String, String> disclosurePreview;
  final String expiry;
  final String? pairwiseAid;

  LoginPreview({
    required this.sessionToken,
    required this.rpSessionUrl,
    required this.siteAid,
    required this.siteOobi,
    required this.audience,
    required this.requestedDisclosures,
    required this.disclosurePreview,
    required this.expiry,
    this.pairwiseAid,
  });

  factory LoginPreview.fromJson(Map<String, dynamic> json) {
    return LoginPreview(
      sessionToken: json['session_token'] ?? '',
      rpSessionUrl: json['rp_session_url'] ?? '',
      siteAid: json['site_aid'] ?? '',
      siteOobi: json['site_oobi'] ?? '',
      audience: json['audience'] ?? '',
      requestedDisclosures:
          List<String>.from(json['requested_disclosures'] ?? []),
      disclosurePreview: Map<String, String>.from(
        (json['disclosure_preview'] as Map?)?.map(
              (k, v) => MapEntry(k.toString(), v.toString()),
            ) ??
            {},
      ),
      expiry: json['expiry'] ?? '',
      pairwiseAid: json['pairwise_aid'],
    );
  }

  String get siteLabel {
    if (audience.isNotEmpty) {
      final uri = Uri.tryParse(audience);
      if (uri != null && uri.host.isNotEmpty) return uri.host;
      return audience;
    }
    return siteAid.length > 12 ? '${siteAid.substring(0, 12)}...' : siteAid;
  }
}

class LoginService {
  final String baseUrl;
  final http.Client _client;

  LoginService({String? baseUrl, http.Client? client})
      : baseUrl = baseUrl ?? AgentConfig.coreBaseUrl,
        _client = client ?? http.Client();

  Uri _uri(String path) => Uri.parse('$baseUrl/api/login$path');

  Future<LoginPreview> preview({
    required String sessionToken,
    required String rpSessionUrl,
  }) async {
    final resp = await _client.post(
      _uri('/preview'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'session_token': sessionToken,
        'rp_session_url': rpSessionUrl,
      }),
    );
    if (resp.statusCode != 200) {
      throw Exception('login preview failed: ${resp.statusCode} ${resp.body}');
    }
    return LoginPreview.fromJson(jsonDecode(resp.body));
  }

  Future<Map<String, dynamic>> approve({
    required String sessionToken,
    required String rpSessionUrl,
  }) async {
    final resp = await _client.post(
      _uri('/approve'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'session_token': sessionToken,
        'rp_session_url': rpSessionUrl,
      }),
    );
    if (resp.statusCode != 200) {
      throw Exception('login approve failed: ${resp.statusCode} ${resp.body}');
    }
    return Map<String, dynamic>.from(jsonDecode(resp.body));
  }

  Future<void> decline({
    required String sessionToken,
    required String rpSessionUrl,
  }) async {
    final resp = await _client.post(
      _uri('/decline'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'session_token': sessionToken,
        'rp_session_url': rpSessionUrl,
      }),
    );
    if (resp.statusCode != 200) {
      throw Exception('login decline failed: ${resp.statusCode}');
    }
  }

  void dispose() => _client.close();
}