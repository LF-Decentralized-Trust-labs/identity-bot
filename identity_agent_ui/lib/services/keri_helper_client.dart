import 'dart:convert';
import 'package:http/http.dart' as http;
import '../config/agent_config.dart';

class FormatCredentialResult {
  final List<int> rawBytes;
  final String schemaId;

  FormatCredentialResult({
    required this.rawBytes,
    required this.schemaId,
  });
}

class ResolvedOobi {
  final String url;
  final List<Map<String, dynamic>> witnesses;

  ResolvedOobi({
    required this.url,
    required this.witnesses,
  });
}

class MultisigEventResult {
  final List<int> eventBytes;
  final String eventType;
  final List<String> participantAids;

  MultisigEventResult({
    required this.eventBytes,
    required this.eventType,
    required this.participantAids,
  });
}

class KeriHelperClient {
  final String _helperUrl;
  final http.Client _client;

  KeriHelperClient({String? helperUrl})
      : _helperUrl = helperUrl ?? AgentConfig.keriHelperUrl,
        _client = http.Client();

  Future<FormatCredentialResult> formatCredential({
    required Map<String, dynamic> claims,
    required String schemaSaid,
    required String issuerAid,
  }) async {
    final response = await _client.post(
      Uri.parse('$_helperUrl/helper/format-credential'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'claims': claims,
        'schema_said': schemaSaid,
        'issuer_aid': issuerAid,
      }),
    );

    if (response.statusCode == 200) {
      final json = jsonDecode(response.body);
      final rawBytesB64 = json['raw_bytes_b64'] as String;
      return FormatCredentialResult(
        rawBytes: base64Decode(rawBytesB64),
        schemaId: json['said'] ?? schemaSaid,
      );
    } else {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Format credential failed: ${response.statusCode}');
    }
  }

  Future<ResolvedOobi> resolveOobi({
    required String oobiUrl,
  }) async {
    final response = await _client.post(
      Uri.parse('$_helperUrl/helper/resolve-oobi'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'url': oobiUrl,
      }),
    );

    if (response.statusCode == 200) {
      final json = jsonDecode(response.body);
      return ResolvedOobi(
        url: json['oobi_url'] ?? oobiUrl,
        witnesses: List<Map<String, dynamic>>.from(json['endpoints'] ?? []),
      );
    } else {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'OOBI resolution failed: ${response.statusCode}');
    }
  }

  Future<MultisigEventResult> generateMultisigEvent({
    required List<String> aids,
    required int threshold,
    required List<String> currentKeys,
  }) async {
    final response = await _client.post(
      Uri.parse('$_helperUrl/helper/generate-multisig-event'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'aids': aids,
        'threshold': threshold,
        'current_keys': currentKeys,
        'event_type': 'inception',
      }),
    );

    if (response.statusCode == 200) {
      final json = jsonDecode(response.body);
      final eventBytesB64 = json['raw_bytes_b64'] as String;
      return MultisigEventResult(
        eventBytes: base64Decode(eventBytesB64),
        eventType: json['event_type'] ?? '',
        participantAids: aids,
      );
    } else {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Multisig event generation failed: ${response.statusCode}');
    }
  }

  void dispose() {
    _client.close();
  }
}
