import 'dart:convert';
import 'package:http/http.dart' as http;
import '../config/agent_config.dart';

/// One credential the site asks you to present, as the consent screen needs to
/// describe it: what is asked, whether it is optional, and whether approving
/// would actually present something.
class LoginCredentialRequest {
  final String schemaSaid;
  final bool required;
  final bool held;

  const LoginCredentialRequest({
    required this.schemaSaid,
    this.required = false,
    this.held = false,
  });

  factory LoginCredentialRequest.fromJson(Map<String, dynamic> json) {
    return LoginCredentialRequest(
      schemaSaid: json['schema_said']?.toString() ?? '',
      required: json['required'] == true,
      held: json['held'] == true,
    );
  }

  String get shortSaid =>
      schemaSaid.length > 12 ? '${schemaSaid.substring(0, 12)}\u2026' : schemaSaid;

  /// What approving would actually do — including presenting nothing, which is
  /// what a user needs to see before a site refuses them for it.
  String get consentValue {
    if (held) return required ? 'required — will be presented' : 'optional — will be presented';
    return required
        ? 'required — you hold none, sign-in may be refused'
        : 'optional — you hold none, nothing presented';
  }
}

/// Set when the site asks for a trust-score attestation.
class LoginScoreRequest {
  final String minBand;
  final int minScore;
  final bool required;

  const LoginScoreRequest({
    this.minBand = '',
    this.minScore = 0,
    this.required = false,
  });

  factory LoginScoreRequest.fromJson(Map<String, dynamic> json) {
    return LoginScoreRequest(
      minBand: json['min_band']?.toString() ?? '',
      minScore: (json['min_score'] as num?)?.toInt() ?? 0,
      required: json['required'] == true,
    );
  }

  String get consentValue {
    var v = 'your trust score is shared';
    if (minBand.isNotEmpty) {
      v += ' (site asks for band $minBand or better)';
    } else if (minScore > 0) {
      v += ' (site asks for $minScore or better)';
    }
    return required ? '$v — required' : v;
  }
}

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

  /// The rest of what the site asks for. A consent screen that lists only the
  /// profile fields describes a smaller request than the one being approved.
  final List<LoginCredentialRequest> requestedCredentials;
  final LoginScoreRequest? requestedScore;

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
    this.requestedCredentials = const [],
    this.requestedScore,
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
      requestedCredentials: ((json['requested_credentials'] as List<dynamic>?) ?? [])
          .map((e) => LoginCredentialRequest.fromJson(e as Map<String, dynamic>))
          .toList(),
      requestedScore: json['requested_score'] == null
          ? null
          : LoginScoreRequest.fromJson(
              json['requested_score'] as Map<String, dynamic>),
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