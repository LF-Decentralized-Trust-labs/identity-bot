import 'dart:convert';
import 'package:http/http.dart' as http;
import 'the_agent_this_app_talks_to.dart';

class PairwiseCheck {
  final int contactIndex;
  final String? contactAid;
  final String pairwiseAid;
  final bool matched;

  PairwiseCheck({
    required this.contactIndex,
    this.contactAid,
    required this.pairwiseAid,
    required this.matched,
  });

  factory PairwiseCheck.fromJson(Map<String, dynamic> json) {
    return PairwiseCheck(
      contactIndex: json['contact_index'] ?? 0,
      contactAid: json['contact_aid'],
      pairwiseAid: json['pairwise_aid'] ?? '',
      matched: json['matched'] ?? false,
    );
  }
}

class RecoveryVerifyResult {
  final bool valid;
  final String? identityAid;
  final int sectionCount;
  final List<PairwiseCheck> pairwiseChecks;

  RecoveryVerifyResult({
    required this.valid,
    this.identityAid,
    required this.sectionCount,
    required this.pairwiseChecks,
  });

  factory RecoveryVerifyResult.fromJson(Map<String, dynamic> json) {
    return RecoveryVerifyResult(
      valid: json['valid'] ?? false,
      identityAid: json['identity_aid'],
      sectionCount: json['section_count'] ?? 0,
      pairwiseChecks: (json['pairwise_checks'] as List<dynamic>? ?? [])
          .map((e) => PairwiseCheck.fromJson(e as Map<String, dynamic>))
          .toList(),
    );
  }
}

class RecoverySession {
  final String id;
  final String state;
  final String? identityAid;
  final String startedAt;
  final String completeAfter;
  final String cancelWindow;
  final String assuranceBand;
  final bool rotationDone;

  RecoverySession({
    required this.id,
    required this.state,
    this.identityAid,
    required this.startedAt,
    required this.completeAfter,
    required this.cancelWindow,
    required this.assuranceBand,
    required this.rotationDone,
  });

  factory RecoverySession.fromJson(Map<String, dynamic> json) {
    return RecoverySession(
      id: json['id'] ?? '',
      state: json['state'] ?? '',
      identityAid: json['identity_aid'],
      startedAt: json['started_at'] ?? '',
      completeAfter: json['complete_after'] ?? '',
      cancelWindow: json['cancel_window'] ?? '',
      assuranceBand: json['assurance_band'] ?? '',
      rotationDone: json['rotation_done'] ?? false,
    );
  }
}

class RecoveryRetrieveResult {
  final String source;
  final String archiveB64;
  final int sizeBytes;
  final String? path;

  RecoveryRetrieveResult({
    required this.source,
    required this.archiveB64,
    required this.sizeBytes,
    this.path,
  });

  factory RecoveryRetrieveResult.fromJson(Map<String, dynamic> json) {
    return RecoveryRetrieveResult(
      source: json['source'] ?? '',
      archiveB64: json['archive_b64'] ?? '',
      sizeBytes: json['size_bytes'] ?? 0,
      path: json['path'],
    );
  }
}

class RootAidRotationStatus {
  final bool available;
  final String? message;
  final int? rotationCount;
  final String? currentRootAid;
  final String? lastRotationAt;

  RootAidRotationStatus({
    required this.available,
    this.message,
    this.rotationCount,
    this.currentRootAid,
    this.lastRotationAt,
  });

  factory RootAidRotationStatus.fromJson(Map<String, dynamic> json) {
    return RootAidRotationStatus(
      available: json['available'] ?? false,
      message: json['message'],
      rotationCount: json['rotation_count'],
      currentRootAid: json['current_root_aid'],
      lastRotationAt: json['last_rotation_at'],
    );
  }
}

class RootAidRotationResult {
  final String status;
  final String message;
  final String oldRootAid;
  final String newRootAid;
  final String newInceptionSaid;
  final String authorizationEventSaid;
  final String? backAnchorEventSaid;
  final int notificationsSent;
  final List<String> carriedForwardAids;

  RootAidRotationResult({
    required this.status,
    required this.message,
    required this.oldRootAid,
    required this.newRootAid,
    required this.newInceptionSaid,
    required this.authorizationEventSaid,
    this.backAnchorEventSaid,
    required this.notificationsSent,
    required this.carriedForwardAids,
  });

  factory RootAidRotationResult.fromJson(Map<String, dynamic> json) {
    final proof = json['continuity_proof'] as Map<String, dynamic>? ?? {};
    return RootAidRotationResult(
      status: json['status'] ?? '',
      message: json['message'] ?? '',
      oldRootAid: json['old_root_aid'] ?? '',
      newRootAid: json['new_root_aid'] ?? '',
      newInceptionSaid: proof['new_inception_said'] ?? '',
      authorizationEventSaid: proof['authorization_event_said'] ?? '',
      backAnchorEventSaid: proof['back_anchor_event_said'],
      notificationsSent: json['notifications_sent'] ?? 0,
      carriedForwardAids: (json['carried_forward_aids'] as List<dynamic>? ?? [])
          .map((e) => e.toString())
          .toList(),
    );
  }
}

class RecoveryService {
  final String baseUrl;
  final http.Client _client;

  /// The agent, not this computer.
  ///
  /// Recovery restores an IDENTITY, and in controller mode this installation
  /// holds none — so the local core would answer about nothing and say so as
  /// though it were the truth about the person's identity.
  ///
  /// It also needs a client that proves who is asking. Recovery is owner-only
  /// on an agent somebody reaches over a network, and the top-level http
  /// functions used here before sent nothing, so every one of these calls was
  /// refused the moment the agent was not on this machine.
  RecoveryService({String? baseUrl, http.Client? client})
      : baseUrl = baseUrl ?? TheAgentThisAppTalksTo.origin,
        _client = client ?? TheAgentThisAppTalksTo.clientFor(baseUrl);

  String get _base => '$baseUrl/api/recovery';

  Future<RecoveryVerifyResult> verify({
    required String mnemonic,
    required String archiveB64,
    String? passphrase,
  }) async {
    final resp = await _client.post(
      Uri.parse('$_base/verify'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'mnemonic': mnemonic,
        if (passphrase != null) 'passphrase': passphrase,
        'archive_b64': archiveB64,
      }),
    );
    if (resp.statusCode != 200) {
      throw Exception(_errorMessage(resp));
    }
    return RecoveryVerifyResult.fromJson(
        jsonDecode(resp.body) as Map<String, dynamic>);
  }

  Future<RecoverySession> start({
    required String mnemonic,
    required String archiveB64,
    String? passphrase,
  }) async {
    final resp = await _client.post(
      Uri.parse('$_base/start'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'mnemonic': mnemonic,
        if (passphrase != null) 'passphrase': passphrase,
        'archive_b64': archiveB64,
      }),
    );
    if (resp.statusCode != 201) {
      throw Exception(_errorMessage(resp));
    }
    return RecoverySession.fromJson(
        jsonDecode(resp.body) as Map<String, dynamic>);
  }

  Future<RecoverySession> getSession(String id) async {
    final resp = await _client.get(Uri.parse('$_base/sessions/$id'));
    if (resp.statusCode != 200) {
      throw Exception(_errorMessage(resp));
    }
    return RecoverySession.fromJson(
        jsonDecode(resp.body) as Map<String, dynamic>);
  }

  Future<RecoveryRetrieveResult> retrieveFromLocal(String localPath) async {
    return _retrieve({'source': 'local_file', 'local_path': localPath});
  }

  Future<RecoveryRetrieveResult> retrieveFromBackupOnly({
    required String identityAid,
    String? archiveName,
  }) async {
    return _retrieve({
      'source': 'backup_only_device',
      'identity_aid': identityAid,
      if (archiveName != null) 'archive_name': archiveName,
    });
  }

  Future<RecoveryRetrieveResult> retrieveFromCloud(String cloudRef) async {
    return _retrieve({'source': 'cloud', 'cloud_ref': cloudRef});
  }

  Future<RecoveryRetrieveResult> _retrieve(Map<String, dynamic> body) async {
    final resp = await _client.post(
      Uri.parse('$_base/retrieve'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(body),
    );
    if (resp.statusCode != 200) {
      throw Exception(_errorMessage(resp));
    }
    return RecoveryRetrieveResult.fromJson(
        jsonDecode(resp.body) as Map<String, dynamic>);
  }

  Future<RootAidRotationStatus> rootAidRotationStatus() async {
    final resp = await _client.get(Uri.parse('$_base/root-aid-rotation/status'));
    if (resp.statusCode != 200) {
      throw Exception(_errorMessage(resp));
    }
    return RootAidRotationStatus.fromJson(
        jsonDecode(resp.body) as Map<String, dynamic>);
  }

  Future<RootAidRotationResult> rotateRootAid({
    required String recoverySessionId,
    required String newRootPublicKey,
    required String newRootNextPublicKey,
    required String preRotationPublicKey,
    required String preRotationNextPublicKey,
    required String authorizationCesrSignature,
    List<String> carryForwardAids = const [],
    int witnessThreshold = 0,
    String? backAnchorCesrSignature,
  }) async {
    final resp = await _client.post(
      Uri.parse('$_base/root-aid-rotation'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'recovery_session_id': recoverySessionId,
        'new_root_public_key': newRootPublicKey,
        'new_root_next_public_key': newRootNextPublicKey,
        'pre_rotation_public_key': preRotationPublicKey,
        'pre_rotation_next_public_key': preRotationNextPublicKey,
        'authorization_cesr_signature': authorizationCesrSignature,
        if (carryForwardAids.isNotEmpty) 'carry_forward_aids': carryForwardAids,
        if (witnessThreshold > 0) 'witness_threshold': witnessThreshold,
        if (backAnchorCesrSignature != null)
          'back_anchor_cesr_signature': backAnchorCesrSignature,
      }),
    );
    if (resp.statusCode != 200) {
      throw Exception(_errorMessage(resp));
    }
    return RootAidRotationResult.fromJson(
        jsonDecode(resp.body) as Map<String, dynamic>);
  }

  String _errorMessage(http.Response resp) {
    try {
      final body = jsonDecode(resp.body) as Map<String, dynamic>;
      final details = body['details'] ?? body['error'] ?? body['message'];
      if (details != null) return '$details (${resp.statusCode})';
    } catch (_) {}
    return 'Recovery request failed (${resp.statusCode}): ${resp.body}';
  }
}