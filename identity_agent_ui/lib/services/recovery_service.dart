import 'dart:convert';
import 'package:http/http.dart' as http;
import '../config/agent_config.dart';

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

class RecoveryService {
  final String baseUrl;

  RecoveryService({String? baseUrl})
      : baseUrl = baseUrl ?? AgentConfig.backendUrl;

  String get _base => '$baseUrl/api/recovery';

  Future<RecoveryVerifyResult> verify({
    required String mnemonic,
    required String archiveB64,
    String? passphrase,
  }) async {
    final resp = await http.post(
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
    final resp = await http.post(
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
    final resp = await http.get(Uri.parse('$_base/sessions/$id'));
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
    final resp = await http.post(
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

  String _errorMessage(http.Response resp) {
    try {
      final body = jsonDecode(resp.body) as Map<String, dynamic>;
      final details = body['details'] ?? body['error'] ?? body['message'];
      if (details != null) return '$details (${resp.statusCode})';
    } catch (_) {}
    return 'Recovery request failed (${resp.statusCode}): ${resp.body}';
  }
}