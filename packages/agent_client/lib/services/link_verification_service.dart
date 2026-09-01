import 'dart:convert';
import 'package:http/http.dart' as http;
import 'the_agent_this_app_talks_to.dart';

/// VerificationResult mirror for Flutter surfaces, matching the link verification contract.
class VerificationResult {
  final String outcome;
  final String? aid;
  final String verificationPath;
  final String? kelReplay;
  final String lastVerified;
  final String? contactCorrelation;
  final LinkOwnership? ownership;
  final String? band;
  final String? bandStyle;
  final int? identityLevelScore;
  final String? identityLevelScoreAsOf;
  final String? badge;
  final bool cached;

  const VerificationResult({
    required this.outcome,
    this.aid,
    required this.verificationPath,
    this.kelReplay,
    required this.lastVerified,
    this.contactCorrelation,
    this.ownership,
    this.band,
    this.bandStyle,
    this.identityLevelScore,
    this.identityLevelScoreAsOf,
    this.badge,
    this.cached = false,
  });

  factory VerificationResult.fromJson(Map<String, dynamic> json) {
    LinkOwnership? ownership;
    if (json['ownership'] is Map<String, dynamic>) {
      ownership = LinkOwnership.fromJson(
        json['ownership'] as Map<String, dynamic>,
      );
    }
    return VerificationResult(
      outcome: json['outcome'] as String? ?? 'unverified',
      aid: json['aid'] as String?,
      verificationPath: json['verification_path'] as String? ?? 'none',
      kelReplay: json['kel_replay'] as String?,
      lastVerified: json['last_verified'] as String? ?? '',
      contactCorrelation: json['contact_correlation'] as String?,
      ownership: ownership,
      band: json['band'] as String?,
      bandStyle: json['band_style'] as String?,
      identityLevelScore: json['identity_level_score'] as int?,
      identityLevelScoreAsOf: json['identity_level_score_as_of'] as String?,
      badge: json['badge'] as String?,
      cached: json['cached'] as bool? ?? false,
    );
  }

  static VerificationResult neutral() => VerificationResult(
        outcome: 'unverified',
        verificationPath: 'none',
        lastVerified: DateTime.now().toUtc().toIso8601String(),
        band: 'gray',
        bandStyle: 'generic',
      );
}

class LinkOwnership {
  final String registeredTo;
  final String disclosure;

  const LinkOwnership({
    required this.registeredTo,
    required this.disclosure,
  });

  factory LinkOwnership.fromJson(Map<String, dynamic> json) => LinkOwnership(
        registeredTo: json['registered_to'] as String? ?? '',
        disclosure: json['disclosure'] as String? ?? 'undisclosed_verified',
      );
}

/// Calls the loopback GET /api/verification/badge on the local Go Core.
class LinkVerificationService {
  final http.Client _client;
  final String? _baseUrl;

  LinkVerificationService({http.Client? client, String? baseUrl})
      : _client = client ?? TheAgentThisAppTalksTo.clientFor(baseUrl),
        _baseUrl = baseUrl;

  /// The agent, not this computer. A link is verified as the IDENTITY, so in
  /// controller mode this has to leave the machine — asking the local core
  /// would ask a core that holds no identity and get a plausible answer about
  /// nobody.
  String get baseUrl => _baseUrl ?? TheAgentThisAppTalksTo.origin;

  Future<VerificationResult> verify({
    required String input,
    String flow = 'link',
    String tier = 'free',
    bool forceRefresh = false,
  }) async {
    if (baseUrl.isEmpty) {
      return VerificationResult.neutral();
    }
    final params = <String, String>{
      'url': input,
      'flow': flow,
      'tier': tier,
    };
    if (forceRefresh) {
      params['refresh'] = '1';
    }
    final uri = Uri.parse('$baseUrl/api/verification/badge')
        .replace(queryParameters: params);
    try {
      final res = await _client.get(uri);
      if (res.statusCode != 200) {
        return VerificationResult.neutral();
      }
      final json = jsonDecode(res.body) as Map<String, dynamic>;
      return VerificationResult.fromJson(json);
    } catch (_) {
      return VerificationResult.neutral();
    }
  }
}