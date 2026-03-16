import 'dart:convert';
import 'package:http/http.dart' as http;
import 'keri_service.dart';
import '../bridge/keri_bridge_stub.dart'
    if (dart.library.io) '../bridge/keri_bridge.dart';

class MobileRemoteKeriService extends KeriService {
  final KeriBridge _bridge;
  final String parentServerUrl;
  final http.Client _client;

  MobileRemoteKeriService({
    required this.parentServerUrl,
    KeriBridge? bridge,
  })  : _bridge = bridge ?? KeriBridge(),
        _client = http.Client();

  @override
  AgentEnvironment get environment => AgentEnvironment.mobileRemoteWithoutKeys;

  @override
  Future<InceptionResult> inceptAid({
    required String name,
    required String code,
  }) async {
    final result = await _bridge.inceptAid(name: name, code: code);
    return InceptionResult(
      aid: result.aid,
      publicKey: result.publicKey,
      kel: result.kel,
      created: DateTime.now().toIso8601String(),
    );
  }

  @override
  Future<RotationResult> rotateAid({required String name}) async {
    final result = await _bridge.rotateAid(name: name);
    return RotationResult(
      aid: result.aid,
      newPublicKey: result.newPublicKey,
      kel: result.kel,
    );
  }

  @override
  Future<SignatureResult> signPayload({
    required String name,
    required List<int> data,
  }) async {
    final result = await _bridge.signPayload(name: name, data: data);
    return SignatureResult(
      signature: result.signature,
      publicKey: result.publicKey,
    );
  }

  @override
  Future<String> getCurrentKel({required String name}) async {
    return await _bridge.getCurrentKel(name: name);
  }

  @override
  Future<bool> verifySignature({
    required List<int> data,
    required String signature,
    required String publicKey,
  }) async {
    return await _bridge.verifySignature(
      data: data,
      signature: signature,
      publicKey: publicKey,
    );
  }

  @override
  Future<InteractResult> interactAid({
    required String name,
    List<Map<String, String>> sealData = const [],
  }) async {
    final sealDataJson = jsonEncode(sealData);
    final ixn = await _bridge.interactAid(name: name, sealDataJson: sealDataJson);

    // Sign the IXN event bytes locally.
    final rawBytes = base64.decode(ixn.rawBytesB64);
    final sigResult = await _bridge.signPayload(name: name, data: rawBytes);
    final cesrSig = await _bridge.cesrEncode(rawSigB64: sigResult.signature);

    // Sync the IXN event to the parent server for persistence.
    try {
      await _client.post(
        Uri.parse('$parentServerUrl/api/store/event'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'aid': ixn.aid,
          'event_type': 'ixn',
          'sequence_number': ixn.sequenceNumber,
          'event_json': ixn.kelEntry,
          'cesr_signature': cesrSig,
        }),
      );
    } catch (_) {}

    return InteractResult(
      aid: ixn.aid,
      said: ixn.said,
      sequenceNumber: ixn.sequenceNumber,
      cesrSignature: cesrSig,
    );
  }

  @override
  Future<CredentialIssuanceResult> issueCredential({
    required Map<String, dynamic> claims,
    required String schemaSaid,
    String holderAid = '',
    String name = '',
  }) async {
    // 1. Format ACDC on parent server (which has the Python KERI driver for SAID computation).
    final fmtResponse = await _client.post(
      Uri.parse('$parentServerUrl/api/format-credential'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'claims': claims,
        'schema_said': schemaSaid,
        'holder_aid': holderAid,
      }),
    );
    if (fmtResponse.statusCode != 200) {
      final body = _tryDecodeJson(fmtResponse.body);
      throw Exception(body['error'] ?? 'format-credential failed: ${fmtResponse.statusCode}');
    }
    final fmtJson = jsonDecode(fmtResponse.body) as Map<String, dynamic>;
    final acdcSaid = fmtJson['said'] as String? ?? '';
    final acdcJsonB64 = fmtJson['raw_bytes_b64'] as String? ?? '';

    // 2. Anchor via local IXN event (Rust bridge).
    final issuerAid = fmtJson['issuer_aid'] as String? ?? '';
    final ixnResult = await interactAid(
      name: name,
      sealData: [
        {'d': acdcSaid, 'i': issuerAid, 's': schemaSaid},
      ],
    );

    return CredentialIssuanceResult(
      acdcSaid: acdcSaid,
      acdcJsonB64: acdcJsonB64,
      ixnRawBytesB64: '',
      ixnSaid: ixnResult.said,
      sequenceNumber: ixnResult.sequenceNumber,
      cesrSignature: ixnResult.cesrSignature,
    );
  }

  @override
  Future<PresentationResult> presentCredential({
    required String acdcSaid,
    required String holderAid,
    String issuerAid = '',
    String schemaSaid = '',
  }) async {
    final response = await _client.post(
      Uri.parse('$parentServerUrl/api/credential/present'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'acdc_said': acdcSaid,
        'holder_aid': holderAid,
        'issuer_aid': issuerAid,
        'schema_said': schemaSaid,
      }),
    );
    if (response.statusCode != 200 && response.statusCode != 201) {
      final body = _tryDecodeJson(response.body);
      throw Exception(body['error'] ?? 'presentCredential failed: ${response.statusCode}');
    }
    final json = jsonDecode(response.body) as Map<String, dynamic>;
    final presentationSaid = json['presentation_said'] as String? ?? '';
    final presentationJsonB64 = json['presentation_json_b64'] as String? ?? '';
    final presSaidB64 = json['pres_said_b64'] as String? ?? '';

    // Sign the presentation SAID bytes locally with the holder key.
    final presSaidBytes = base64.decode(presSaidB64);
    final sigResult = await _bridge.signPayload(name: holderAid, data: presSaidBytes);
    final cesrSig = await _bridge.cesrEncode(rawSigB64: sigResult.signature);

    return PresentationResult(
      presentationSaid: presentationSaid,
      presentationJsonB64: presentationJsonB64,
      cesrSignature: cesrSig,
    );
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
      Uri.parse('$parentServerUrl/api/credential/verify'),
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
    if (response.statusCode != 200) {
      final body = _tryDecodeJson(response.body);
      throw Exception(body['error'] ?? 'verifyCredential failed: ${response.statusCode}');
    }
    final json = jsonDecode(response.body) as Map<String, dynamic>;
    return VerificationResult(
      verified: json['verified'] == true,
      checks: (json['checks'] as Map<String, dynamic>?) ?? {},
      errors: List<String>.from(json['errors'] ?? []),
      acdcSaid: json['acdc_said'] as String? ?? '',
    );
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
      Uri.parse('$parentServerUrl/api/receipt/submit'),
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
    if (response.statusCode != 200) {
      final body = _tryDecodeJson(response.body);
      throw Exception(body['error'] ?? 'submitWitnessReceipt failed: ${response.statusCode}');
    }
    final json = jsonDecode(response.body) as Map<String, dynamic>;
    return WitnessReceiptResult(
      accepted: json['accepted'] == true,
      thresholdMet: json['threshold_met'] == true,
      receiptCount: (json['receipt_count'] as int?) ?? 0,
      errors: List<String>.from(json['errors'] ?? []),
    );
  }

  @override
  Future<KerlEntry> getKERL({
    required String eventSaid,
    int threshold = 0,
  }) async {
    final response = await _client.get(
      Uri.parse('$parentServerUrl/api/kerl?event_said=$eventSaid&threshold=$threshold'),
    );
    if (response.statusCode == 200) {
      final json = jsonDecode(response.body) as Map<String, dynamic>;
      final rawReceipts = (json['receipts'] as List<dynamic>?) ?? [];
      final receipts = rawReceipts
          .map((r) => Map<String, dynamic>.from(r as Map))
          .toList();
      return KerlEntry(
        eventSaid: eventSaid,
        receipts: receipts,
        receiptCount: (json['receipt_count'] as int?) ?? receipts.length,
        thresholdMet: json['threshold_met'] == true,
      );
    }
    throw Exception('getKERL failed: ${response.statusCode}');
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
