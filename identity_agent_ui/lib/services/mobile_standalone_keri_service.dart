import 'dart:convert';
import 'package:http/http.dart' as http;
import 'keri_service.dart';
import 'mobile_core_service.dart';
import '../bridge/keri_bridge_stub.dart'
    if (dart.library.io) '../bridge/keri_bridge.dart';
import '../config/agent_config.dart';

class MobileStandaloneKeriService extends KeriService {
  final KeriBridge _bridge;
  final MobileCoreService _mobileCore;
  final String _keriServiceUrl;
  final http.Client _client;
  bool _coreStarted = false;

  MobileStandaloneKeriService({
    KeriBridge? bridge,
    MobileCoreService? mobileCore,
    String? keriServiceUrl,
  })  : _bridge = bridge ?? KeriBridge(),
        _mobileCore = mobileCore ?? MobileCoreService(),
        _keriServiceUrl = keriServiceUrl ?? AgentConfig.publicKeriServiceUrl,
        _client = http.Client();

  @override
  AgentEnvironment get environment => AgentEnvironment.mobileStandalone;

  MobileCoreService get mobileCore => _mobileCore;

  bool get isCoreReady => _coreStarted;

  Future<void> startGoCore({String? dataDir, int? port}) async {
    if (_coreStarted) return;

    await _mobileCore.startCore(dataDir: dataDir, port: port);
    final ready = await _mobileCore.waitForReady();
    if (!ready) {
      throw Exception('Go Core server did not become ready within timeout');
    }
    _coreStarted = true;
  }

  Future<void> stopGoCore() async {
    if (!_coreStarted) return;
    await _mobileCore.stopCore();
    _coreStarted = false;
  }

  String get _coreUrl => AgentConfig.coreBaseUrl;

  // ---------------------------------------------------------------------------
  // CESR / key conversion helpers
  // ---------------------------------------------------------------------------

  /// Decode a CESR '0B...' (88-char) signature to raw base64 (standard, 88 chars → 64 bytes).
  ///
  /// CESR encoding: prepend 2 lead bytes [0x00,0x00] → 66 bytes → base64url (no pad) → 88 chars
  ///                then replace chars [0,2] with '0B'.
  /// Since lead bytes are always \x00\x00, their base64url prefix is 'AA'.
  String _cesrSigToRawBase64(String cesrSig) {
    if (!cesrSig.startsWith('0B') || cesrSig.length != 88) {
      throw ArgumentError('Expected CESR Ed25519 sig (0B..., 88 chars), got: $cesrSig');
    }
    // Reconstruct original base64url: replace '0B' → 'AA'.
    final b64url = 'AA${cesrSig.substring(2)}'; // 88 chars → 66 bytes when decoded
    final decoded = base64Url.decode(b64url); // Dart pads internally if needed
    final raw64 = decoded.sublist(2); // drop 2 lead bytes → 64 bytes
    return base64.encode(raw64);
  }

  /// Decode a CESR Ed25519 public key ('B...' or 'D...', 44 chars) to raw base64 (32 bytes).
  ///
  /// CESR encoding: prepend 1 lead byte [0x00] → 33 bytes → base64url (no pad) → 44 chars
  ///                then replace char[0] with 'B' (NT) or 'D' (transferable).
  /// Since the lead byte is \x00, its base64url prefix char is 'A'.
  String _cesrKeyToRawBase64(String cesrKey) {
    if (cesrKey.length != 44) {
      // Might already be raw base64 (32 bytes → 44 chars with padding, or 43 no-pad).
      return cesrKey;
    }
    final ch = cesrKey[0];
    if (ch == 'B' || ch == 'D') {
      final b64url = 'A${cesrKey.substring(1)}'; // 44 chars → 33 bytes
      final decoded = base64Url.decode(b64url);
      final raw32 = decoded.sublist(1); // drop 1 lead byte → 32 bytes
      return base64.encode(raw32);
    }
    // Assume already raw base64.
    return cesrKey;
  }

  // ---------------------------------------------------------------------------
  // Standard KERI bridge ops (unchanged from original)
  // ---------------------------------------------------------------------------

  @override
  Future<InceptionResult> inceptAid({
    required String name,
    required String code,
  }) async {
    final result = await _bridge.inceptAid(name: name, code: code);

    if (_coreStarted) {
      try {
        await _mobileCore.storeIdentity(
          aid: result.aid,
          publicKey: result.publicKey,
        );
        await _mobileCore.storeEvent(
          aid: result.aid,
          eventType: 'icp',
          sequenceNumber: 0,
          eventJson: result.kel,
          publicKey: result.publicKey,
        );
      } catch (_) {}
    }

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

    if (_coreStarted) {
      try {
        await _mobileCore.storeEvent(
          aid: result.aid,
          eventType: 'rot',
          sequenceNumber: 1,
          eventJson: result.kel,
          publicKey: result.newPublicKey,
        );
      } catch (_) {}
    }

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

  // ---------------------------------------------------------------------------
  // Previously unimplemented methods
  // ---------------------------------------------------------------------------

  @override
  Future<InteractResult> interactAid({
    required String name,
    List<Map<String, String>> sealData = const [],
  }) async {
    final sealDataJson = jsonEncode(sealData);
    final ixn = await _bridge.interactAid(name: name, sealDataJson: sealDataJson);

    // Sign the raw IXN event bytes.
    final rawBytes = base64.decode(ixn.rawBytesB64);
    final sigResult = await _bridge.signPayload(name: name, data: rawBytes);
    final cesrSig = await _bridge.cesrEncode(rawSigB64: sigResult.signature);

    if (_coreStarted) {
      try {
        final response = await _client.post(
          Uri.parse('$_coreUrl/api/store/event'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({
            'aid': ixn.aid,
            'event_type': 'ixn',
            'sequence_number': ixn.sequenceNumber,
            'event_json': ixn.kelEntry,
            'cesr_signature': cesrSig,
          }),
        );
        if (response.statusCode != 201) {
          // Non-fatal: log but continue.
        }
      } catch (_) {}
    }

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
    // 1. Get the issuer AID from the bridge (we need it for format-credential).
    final identity = _coreStarted ? await _getStoredIdentity() : null;
    final issuerAid = identity?.aid ?? '';

    // 2. Format the ACDC credential via the public KERI service (stateless).
    final fmtResponse = await _client.post(
      Uri.parse('$_keriServiceUrl/format-credential'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'claims': claims,
        'schema_said': schemaSaid,
        'issuer_aid': issuerAid,
      }),
    );
    if (fmtResponse.statusCode != 200) {
      final body = _tryDecodeJson(fmtResponse.body);
      throw Exception(body['error'] ?? 'format-credential failed: ${fmtResponse.statusCode}');
    }
    final fmtJson = jsonDecode(fmtResponse.body) as Map<String, dynamic>;
    final acdcSaid = fmtJson['said'] as String? ?? '';
    final acdcJsonB64 = fmtJson['raw_bytes_b64'] as String? ?? '';

    // 3. Anchor the credential SAID in the KEL via an IXN event.
    final ixnResult = await interactAid(
      name: name,
      sealData: [
        {'d': acdcSaid, 'i': issuerAid, 's': schemaSaid},
      ],
    );

    // 4. Persist the credential in Go Core.
    if (_coreStarted) {
      try {
        await _client.post(
          Uri.parse('$_coreUrl/api/store/credential'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({
            'said': acdcSaid,
            'issuer_aid': issuerAid,
            'holder_aid': holderAid,
            'schema_said': schemaSaid,
            'acdc_json_b64': acdcJsonB64,
            'ixn_said': ixnResult.said,
            'cesr_signature': ixnResult.cesrSignature,
            'status': 'issued',
          }),
        );
      } catch (_) {}
    }

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
    // Build the presentation envelope via the public KERI service (stateless).
    final response = await _client.post(
      Uri.parse('$_keriServiceUrl/credential/present'),
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

    // Sign the presentation SAID bytes with the holder's local key.
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
      Uri.parse('$_keriServiceUrl/credential/verify'),
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
    // 1. Verify the receipt signature locally via the Rust bridge.
    final eventSaidBytes = utf8.encode(eventSaid);
    final rawSigB64 = _cesrSigToRawBase64(cesrSignature);
    final rawPkB64 = _cesrKeyToRawBase64(witnessPublicKey);

    bool sigValid = false;
    try {
      sigValid = await _bridge.verifySignature(
        data: List<int>.from(eventSaidBytes),
        signature: rawSigB64,
        publicKey: rawPkB64,
      );
    } catch (e) {
      return WitnessReceiptResult(
        accepted: false,
        thresholdMet: false,
        receiptCount: 0,
        errors: ['Signature verification error: $e'],
      );
    }

    if (!sigValid) {
      return WitnessReceiptResult(
        accepted: false,
        thresholdMet: false,
        receiptCount: 0,
        errors: ['Receipt signature invalid'],
      );
    }

    // 2. Check trust (if trustedWitnesses list is provided).
    if (trustedWitnesses.isNotEmpty && !trustedWitnesses.contains(witnessAid)) {
      return WitnessReceiptResult(
        accepted: false,
        thresholdMet: false,
        receiptCount: 0,
        errors: ['Witness AID not in trusted_witnesses list'],
      );
    }

    // 3. Persist the receipt in Go Core.
    if (_coreStarted) {
      try {
        await _client.post(
          Uri.parse('$_coreUrl/api/store/receipt'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({
            'event_said': eventSaid,
            'witness_aid': witnessAid,
            'cesr_signature': cesrSignature,
          }),
        );
      } catch (_) {}
    }

    // 4. Query current receipt count.
    int receiptCount = 1;
    if (_coreStarted) {
      try {
        final getResp = await _client.get(
          Uri.parse('$_coreUrl/api/store/receipts?event_said=$eventSaid&threshold=$threshold'),
        );
        if (getResp.statusCode == 200) {
          final data = jsonDecode(getResp.body) as Map<String, dynamic>;
          receiptCount = (data['receipt_count'] as int?) ?? receiptCount;
        }
      } catch (_) {}
    }

    final thresholdMet = threshold == 0 || receiptCount >= threshold;

    return WitnessReceiptResult(
      accepted: true,
      thresholdMet: thresholdMet,
      receiptCount: receiptCount,
    );
  }

  @override
  Future<KerlEntry> getKERL({
    required String eventSaid,
    int threshold = 0,
  }) async {
    if (!_coreStarted) {
      return KerlEntry(
        eventSaid: eventSaid,
        receipts: [],
        receiptCount: 0,
        thresholdMet: threshold == 0,
      );
    }

    final response = await _client.get(
      Uri.parse('$_coreUrl/api/kerl?event_said=$eventSaid&threshold=$threshold'),
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

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  Future<_StoredIdentity?> _getStoredIdentity() async {
    try {
      final response = await _client.get(Uri.parse('$_coreUrl/api/identity'));
      if (response.statusCode == 200) {
        final json = jsonDecode(response.body) as Map<String, dynamic>;
        final aid = json['aid'] as String?;
        if (aid != null && aid.isNotEmpty) {
          return _StoredIdentity(aid: aid);
        }
      }
    } catch (_) {}
    return null;
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
    if (_coreStarted) {
      _mobileCore.stopCore();
    }
    _mobileCore.dispose();
    _client.close();
  }
}

class _StoredIdentity {
  final String aid;
  _StoredIdentity({required this.aid});
}
