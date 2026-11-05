import 'dart:convert';

import 'package:http/http.dart' as http;

/// The organisation's AI agents, as the Identity Agent's roster
/// (`GET /api/mcp/agents`) names them — one reader for every app that shows
/// them, so no screen parses the roster its own way.
///
/// The JSON is `{"agents": [ ... ]}`; each entry is the AI-agent add-on's
/// `agentView`. This is the only Dart that knows its keys.
class AiAgent {
  /// The asset id every route about this agent is addressed by.
  final String assetId;

  /// What the roster calls it.
  final String name;

  /// The identity its messages are signed with.
  final String agentAid;

  /// The identity that delegated to it.
  final String delegatorAid;

  /// What its grant lets it do.
  final List<String> capabilities;

  /// The limits on each capability's arguments (who it may message, among
  /// others). Null when the Identity Agent is too old to report them: a screen
  /// must then leave limits alone rather than treat it as "none".
  final Map<String, dynamic>? resourceConstraints;

  /// Its role, as written when it was made.
  final String role;

  /// Its brain's settings (`kind`, `provider`, `model`, `program`), never a secret.
  final Map<String, dynamic> brain;

  /// Its brain's sign-in as it may be shown, or null when it has none here.
  final Map<String, dynamic>? brainSignIn;

  /// `active` or `revoked`. `revoked` includes a grant that was withdrawn and
  /// can be replaced; see [revokedForGood] for the other.
  final String status;

  final DateTime? createdAt;

  /// Its grant waits for the device that holds the identity's key.
  final bool grantPending;

  /// When it was revoked for good, and by whom. A withdrawn grant has neither.
  final DateTime? revokedAt;
  final String revokedBy;

  const AiAgent({
    required this.assetId,
    required this.name,
    required this.agentAid,
    this.delegatorAid = '',
    this.capabilities = const [],
    this.resourceConstraints,
    this.role = '',
    this.brain = const {},
    this.brainSignIn,
    this.status = 'active',
    this.createdAt,
    this.grantPending = false,
    this.revokedAt,
    this.revokedBy = '',
  });

  /// One entry of the roster. Never throws on a missing key; an entry that is
  /// not an object is the caller's to skip (see [AiAgentRoster.list]).
  factory AiAgent.fromJson(Map<String, dynamic> j) {
    final cfg = j['agent_config'];
    final brain = cfg is Map ? cfg['brain'] : null;
    final signIn = j['brain_sign_in'];
    final limits = j['resource_constraints'];
    return AiAgent(
      assetId: _text(j['asset_id']),
      name: _text(j['name']),
      agentAid: _text(j['agent_aid']),
      delegatorAid: _text(j['delegator_aid']),
      capabilities: [
        for (final c in (j['capabilities'] as List? ?? const []))
          if (c is String) c
      ],
      resourceConstraints:
          limits is Map ? Map<String, dynamic>.from(limits) : null,
      role: cfg is Map ? _text(cfg['role']) : '',
      brain: brain is Map ? Map<String, dynamic>.from(brain) : const {},
      brainSignIn:
          signIn is Map ? Map<String, dynamic>.from(signIn) : null,
      status: j['status'] is String ? j['status'] as String : 'active',
      createdAt: DateTime.tryParse(_text(j['created_at'])),
      grantPending: j['grant_pending'] == true,
      revokedAt: DateTime.tryParse(_text(j['revoked_at'])),
      revokedBy: _text(j['revoked_by']),
    );
  }

  /// It can do nothing now: revoked for good, or its grant withdrawn.
  bool get cannotActNow => status == 'revoked' || revokedAt != null;

  /// Revoked for good (ADR-056): never granted anything again.
  bool get revokedForGood => revokedAt != null;

  /// Its brain is signed in with a key that stays with the Identity Agent.
  bool get brainStaysWithIdentityAgent =>
      brainSignIn?['stays_with_identity_agent'] == true;

  /// The provider its brain is signed in with, if it is signed in.
  String? get brainSignInProvider {
    final p = brainSignIn?['provider'];
    return p is String ? p : null;
  }

  static String _text(Object? v) => v is String ? v : '';
}

/// Why the roster could not be read.
class AiAgentRosterException implements Exception {
  final int? statusCode;
  final String message;

  /// The Identity Agent's refusal as it came, for an app that words refusals
  /// its own way. Null when nothing was answered, or what was is not a refusal.
  final http.Response? response;
  const AiAgentRosterException(this.message, {this.statusCode, this.response});
  @override
  String toString() => message;
}

/// Reads the organisation's AI agents through its Identity Agent.
///
/// [client] must be one that already carries what the Identity Agent asks of a
/// caller (the app's signing client); this class adds nothing to a request.
class AiAgentRoster {
  final http.Client client;
  final String baseUrl;
  final Duration timeout;

  const AiAgentRoster(this.client, this.baseUrl,
      {this.timeout = const Duration(seconds: 12)});

  /// The roster's path, written once.
  static const path = '/api/mcp/agents';

  /// Every AI agent, revoked ones included. An entry with no asset id, or not
  /// an object, is left out: nothing can be addressed by it.
  ///
  /// Throws [AiAgentRosterException] when the roster cannot be read, so a
  /// screen says so rather than showing nobody. [tryList] is the same, null.
  Future<List<AiAgent>> list() async {
    final http.Response resp;
    try {
      resp = await client.get(Uri.parse('$baseUrl$path')).timeout(timeout);
    } catch (e) {
      throw AiAgentRosterException('The AI agents could not be reached: $e');
    }
    if (resp.statusCode != 200) {
      throw AiAgentRosterException(
          'The AI agents could not be read (HTTP ${resp.statusCode}).',
          statusCode: resp.statusCode, response: resp);
    }
    final Object? decoded;
    try {
      decoded = jsonDecode(resp.body);
    } catch (_) {
      throw const AiAgentRosterException(
          'The AI agents could not be read: the answer was not JSON.');
    }
    final list = decoded is Map ? decoded['agents'] : null;
    if (list is! List) {
      throw const AiAgentRosterException(
          'The AI agents could not be read: the answer had no "agents" list.');
    }
    return [
      for (final a in list)
        if (a is Map<String, dynamic> && a['asset_id'] is String &&
            (a['asset_id'] as String).isNotEmpty)
          AiAgent.fromJson(a)
    ];
  }

  /// [list], or null when the roster cannot be read.
  Future<List<AiAgent>?> tryList() async {
    try {
      return await list();
    } on AiAgentRosterException {
      return null;
    }
  }

  /// One AI agent, or null when the roster does not have it. Throws as [list].
  Future<AiAgent?> read(String assetId) async {
    for (final a in await list()) {
      if (a.assetId == assetId) return a;
    }
    return null;
  }
}
