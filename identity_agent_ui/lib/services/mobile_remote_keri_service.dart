import 'dart:convert';
import 'package:http/http.dart' as http;
import 'keri_service.dart';

/// Mobile KERI service for devices that do NOT hold their own private keys.
///
/// All KERI operations are forwarded to the paired desktop Identity Agent
/// server. The Rust bridge is never used. This is the fallback for the
/// Remote Controller WITHOUT Keys topology (ADR-006) — either when the device
/// is intentionally key-free, or when the Rust bridge fails to load.
class RemoteKeriService extends KeriService {
  final String _serverUrl;
  final http.Client _client;

  RemoteKeriService({required String serverUrl})
      : _serverUrl = serverUrl,
        _client = http.Client();

  @override
  AgentEnvironment get environment => AgentEnvironment.mobileRemoteWithoutKeys;

  @override
  Future<InceptionResult> inceptAid({
    required String name,
    required String code,
  }) async {
    final response = await _client.post(
      Uri.parse('$_serverUrl/api/inception'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'name': name, 'code': code}),
    );
    if (response.statusCode == 201 || response.statusCode == 200) {
      final json = jsonDecode(response.body);
      return InceptionResult(
        aid: json['aid'] ?? '',
        publicKey: json['public_key'] ?? '',
        kel: json['kel'] ?? '',
        created: json['created'] ?? DateTime.now().toIso8601String(),
      );
    }
    final body = _tryDecodeJson(response.body);
    throw Exception(body['error'] ?? 'Remote inception failed: ${response.statusCode}');
  }

  @override
  Future<RotationResult> rotateAid({required String name}) async {
    final response = await _client.post(
      Uri.parse('$_serverUrl/api/rotation'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'name': name}),
    );
    if (response.statusCode == 200) {
      final json = jsonDecode(response.body);
      return RotationResult(
        aid: json['aid'] ?? '',
        newPublicKey: json['new_public_key'] ?? '',
        kel: json['kel'] ?? '',
      );
    }
    final body = _tryDecodeJson(response.body);
    throw Exception(body['error'] ?? 'Remote rotation failed: ${response.statusCode}');
  }

  @override
  Future<SignatureResult> signPayload({
    required String name,
    required List<int> data,
  }) async {
    final response = await _client.post(
      Uri.parse('$_serverUrl/api/sign'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'name': name, 'data': base64Encode(data)}),
    );
    if (response.statusCode == 200) {
      final json = jsonDecode(response.body);
      return SignatureResult(signature: json['signature'] ?? '', publicKey: json['public_key'] ?? '');
    }
    final body = _tryDecodeJson(response.body);
    throw Exception(body['error'] ?? 'Remote signing failed: ${response.statusCode}');
  }

  @override
  Future<String> getCurrentKel({required String name}) async {
    final response = await _client.get(Uri.parse('$_serverUrl/api/kel?name=$name'));
    if (response.statusCode == 200) {
      final json = jsonDecode(response.body);
      return json['kel'] ?? '';
    }
    throw Exception('Remote KEL request failed: ${response.statusCode}');
  }

  @override
  Future<bool> verifySignature({
    required List<int> data,
    required String signature,
    required String publicKey,
  }) async {
    final response = await _client.post(
      Uri.parse('$_serverUrl/api/verify'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'data': base64Encode(data), 'signature': signature, 'public_key': publicKey}),
    );
    if (response.statusCode == 200) {
      final json = jsonDecode(response.body);
      return json['valid'] == true;
    }
    return false;
  }

  @override
  Future<InteractResult> interactAid({
    required String name,
    List<Map<String, String>> sealData = const [],
  }) async {
    final response = await _client.post(
      Uri.parse('$_serverUrl/api/interact'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'name': name, 'data': sealData}),
    );
    if (response.statusCode == 200 || response.statusCode == 201) {
      final json = jsonDecode(response.body) as Map<String, dynamic>;
      return InteractResult(
        aid: json['aid'] as String? ?? '',
        said: json['said'] as String? ?? '',
        sequenceNumber: (json['sequence_number'] as int?) ?? 0,
        cesrSignature: json['cesr_signature'] as String? ?? '',
      );
    }
    final body = _tryDecodeJson(response.body);
    throw Exception(body['error'] ?? 'Remote interactAid failed: ${response.statusCode}');
  }

  @override
  Future<CredentialIssuanceResult> issueCredential({
    required Map<String, dynamic> claims,
    required String schemaSaid,
    String holderAid = '',
    String name = '',
  }) async {
    final response = await _client.post(
      Uri.parse('$_serverUrl/api/credential/issue'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'claims': claims, 'schema_said': schemaSaid, 'holder_aid': holderAid}),
    );
    if (response.statusCode == 200 || response.statusCode == 201) {
      final json = jsonDecode(response.body) as Map<String, dynamic>;
      return CredentialIssuanceResult(
        acdcSaid: json['acdc_said'] as String? ?? '',
        acdcJsonB64: json['acdc_json_b64'] as String? ?? '',
        ixnRawBytesB64: json['ixn_raw_bytes_b64'] as String? ?? '',
        ixnSaid: json['ixn_said'] as String? ?? '',
        sequenceNumber: (json['sequence_number'] as int?) ?? 0,
        cesrSignature: json['cesr_signature'] as String? ?? '',
      );
    }
    final body = _tryDecodeJson(response.body);
    throw Exception(body['error'] ?? 'Remote issueCredential failed: ${response.statusCode}');
  }

  @override
  Future<PresentationResult> presentCredential({
    required String acdcSaid,
    required String holderAid,
    String issuerAid = '',
    String schemaSaid = '',
  }) async {
    final response = await _client.post(
      Uri.parse('$_serverUrl/api/credential/present'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'acdc_said': acdcSaid,
        'holder_aid': holderAid,
        'issuer_aid': issuerAid,
        'schema_said': schemaSaid,
      }),
    );
    if (response.statusCode == 200 || response.statusCode == 201) {
      final json = jsonDecode(response.body) as Map<String, dynamic>;
      return PresentationResult(
        presentationSaid: json['presentation_said'] as String? ?? '',
        presentationJsonB64: json['presentation_json_b64'] as String? ?? '',
        cesrSignature: json['cesr_signature'] as String? ?? '',
      );
    }
    final body = _tryDecodeJson(response.body);
    throw Exception(body['error'] ?? 'Remote presentCredential failed: ${response.statusCode}');
  }

  @override
  Future<VerificationResult> verifyCredential({
    required String acdcJson,
    String holderAid = '',
    String presentationSaid = '',
    String cesrSignature = '',
    String holderPublicKey = '',
    List<String> trustedSchemaSaids = const [],
  }) async {
    final response = await _client.post(
      Uri.parse('$_serverUrl/api/credential/verify'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'acdc_json': acdcJson,
        'holder_aid': holderAid,
        'presentation_said': presentationSaid,
        'cesr_signature': cesrSignature,
        'holder_public_key': holderPublicKey,
        'trusted_schema_saids': trustedSchemaSaids,
      }),
    );
    if (response.statusCode == 200) {
      final json = jsonDecode(response.body) as Map<String, dynamic>;
      return VerificationResult(
        verified: json['verified'] == true,
        checks: (json['checks'] as Map<String, dynamic>?) ?? {},
        errors: List<String>.from(json['errors'] ?? []),
        acdcSaid: json['acdc_said'] as String? ?? '',
      );
    }
    final body = _tryDecodeJson(response.body);
    throw Exception(body['error'] ?? 'Remote verifyCredential failed: ${response.statusCode}');
  }

  @override
  Future<WitnessReceiptResult> submitWitnessReceipt({
    required String eventSaid,
    required String witnessAid,
    required String witnessPublicKey,
    required String cesrSignature,
    List<String> trustedWitnesses = const [],
    int threshold = 0,
  }) async {
    final response = await _client.post(
      Uri.parse('$_serverUrl/api/receipt/submit'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'event_said': eventSaid,
        'witness_aid': witnessAid,
        'witness_public_key': witnessPublicKey,
        'cesr_signature': cesrSignature,
        'trusted_witnesses': trustedWitnesses,
        'threshold': threshold,
      }),
    );
    if (response.statusCode == 200) {
      final json = jsonDecode(response.body) as Map<String, dynamic>;
      return WitnessReceiptResult(
        accepted: json['accepted'] == true,
        thresholdMet: json['threshold_met'] == true,
        receiptCount: (json['receipt_count'] as int?) ?? 0,
        errors: List<String>.from(json['errors'] ?? []),
      );
    }
    final body = _tryDecodeJson(response.body);
    throw Exception(body['error'] ?? 'Remote submitWitnessReceipt failed: ${response.statusCode}');
  }

  @override
  Future<KerlEntry> getKERL({
    required String eventSaid,
    int threshold = 0,
  }) async {
    final response = await _client.get(
      Uri.parse('$_serverUrl/api/kerl?event_said=$eventSaid&threshold=$threshold'),
    );
    if (response.statusCode == 200) {
      final json = jsonDecode(response.body) as Map<String, dynamic>;
      final rawReceipts = (json['receipts'] as List<dynamic>?) ?? [];
      final receipts = rawReceipts.map((r) => Map<String, dynamic>.from(r as Map)).toList();
      return KerlEntry(
        eventSaid: eventSaid,
        receipts: receipts,
        receiptCount: (json['receipt_count'] as int?) ?? receipts.length,
        thresholdMet: json['threshold_met'] == true,
      );
    }
    throw Exception('Remote getKERL failed: ${response.statusCode}');
  }

  Map<String, dynamic> _tryDecodeJson(String body) {
    try {
      return jsonDecode(body) as Map<String, dynamic>;
    } catch (_) {
      return {};
    }
  }

  @override
  void dispose() {
    _client.close();
  }
}
