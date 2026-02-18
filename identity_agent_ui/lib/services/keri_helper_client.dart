import 'dart:convert';
import 'package:http/http.dart' as http;
import '../config/agent_config.dart';

class FormatCredentialResult {
  final List<int> rawBytes;
  final String said;
  final int size;

  FormatCredentialResult({
    required this.rawBytes,
    required this.said,
    required this.size,
  });
}

class ResolvedOobi {
  final String oobiUrl;
  final List<String> endpoints;
  final String cid;
  final String eid;
  final String role;

  ResolvedOobi({
    required this.oobiUrl,
    required this.endpoints,
    required this.cid,
    required this.eid,
    required this.role,
  });
}

class MultisigEventResult {
  final List<int> rawBytes;
  final String said;
  final String pre;
  final String eventType;
  final int size;

  MultisigEventResult({
    required this.rawBytes,
    required this.said,
    required this.pre,
    required this.eventType,
    required this.size,
  });
}

class KeriHelperClient {
  final String _baseUrl;
  final http.Client _client;

  KeriHelperClient({String? baseUrl})
      : _baseUrl = baseUrl ?? AgentConfig.keriHelperUrl,
        _client = http.Client();

  Future<FormatCredentialResult> formatCredential({
    required Map<String, dynamic> claims,
    required String schemaSaid,
    required String issuerAid,
  }) async {
    final response = await _client.post(
      Uri.parse('$_baseUrl/format-credential'),
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
        said: json['said'] ?? '',
        size: json['size'] ?? 0,
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
      Uri.parse('$_baseUrl/resolve-oobi'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'url': oobiUrl,
      }),
    );

    if (response.statusCode == 200) {
      final json = jsonDecode(response.body);
      return ResolvedOobi(
        oobiUrl: json['oobi_url'] ?? oobiUrl,
        endpoints: List<String>.from(json['endpoints'] ?? []),
        cid: json['cid'] ?? '',
        eid: json['eid'] ?? '',
        role: json['role'] ?? '',
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
    String eventType = 'inception',
  }) async {
    final response = await _client.post(
      Uri.parse('$_baseUrl/generate-multisig-event'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'aids': aids,
        'threshold': threshold,
        'current_keys': currentKeys,
        'event_type': eventType,
      }),
    );

    if (response.statusCode == 200) {
      final json = jsonDecode(response.body);
      final rawBytesB64 = json['raw_bytes_b64'] as String;
      return MultisigEventResult(
        rawBytes: base64Decode(rawBytesB64),
        said: json['said'] ?? '',
        pre: json['pre'] ?? '',
        eventType: json['event_type'] ?? '',
        size: json['size'] ?? 0,
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
