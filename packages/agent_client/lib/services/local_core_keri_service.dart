import 'dart:convert';
import 'dart:typed_data';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;
import '../crypto/bip39.dart';
import '../crypto/keys.dart';
import 'keri_service.dart';
import 'secure_key_store.dart';
import 'the_key_is_not_held_by_the_core.dart';
import 'the_agent_this_app_talks_to.dart';

/// KERI against the Identity Agent core running on this machine.
///
/// Named for what it talks to rather than what kind of computer it is on,
/// because it turned out to be right for both. It was DesktopOnDeviceKeriService
/// while mobile had a KERI engine of its own — a Rust library that generated a
/// random key instead of deriving one from the recovery phrase it was given,
/// and held it in memory. Mobile now uses this, against the core running inside
/// the app, so there is one KERI implementation everywhere and the key comes
/// from the words on every platform.
class LocalCoreKeriService extends KeriService {
  final String _baseUrl;
  final http.Client _client;

  LocalCoreKeriService({String? baseUrl, http.Client? client})
      // Where the KEYS are, which is not always this computer.
      //
      // Stateful KERI operations always run on the engine local to the keys —
      // that invariant is about the KEYS, not about this process. When the
      // identity lives on a sealed machine, that machine's engine is the local
      // one and this installation is only the front end.
      : _baseUrl = baseUrl ?? TheAgentThisAppTalksTo.origin,
        _client = client ?? TheAgentThisAppTalksTo.clientFor(baseUrl);

  /// Where this service sends, for a caller checking it is pointed at the
  /// identity rather than at whichever core happens to be on this machine.
  String get baseUrl => _baseUrl;

  @override
  AgentEnvironment get environment => AgentEnvironment.desktop;

  @override
  Future<InceptionResult> inceptAid({
    required String name,
    required String code,
  }) async {
    final mnemonic = code.split(' ');
    final keys = KeyManager.generateKeysFromMnemonic(mnemonic);

    // Step 1: Create the inception event on the Python driver via Go backend.
    final response = await _client.post(
      Uri.parse('$_baseUrl/api/inception'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'public_key': keys.signing.publicKeyEncoded,
        'next_public_key': keys.next.publicKeyEncoded,
      }),
    );

    if (response.statusCode != 201 && response.statusCode != 200) {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Inception failed: ${response.statusCode}');
    }

    final json = jsonDecode(response.body);
    final rawBytesB64 = json['raw_bytes_b64'] as String? ?? '';

    // Step 2: Sign the inception event bytes locally with the Ed25519 key.
    // Private key never leaves this device (ADR-014).
    String cesrSignature = '';
    if (rawBytesB64.isNotEmpty) {
      final seed = Bip39.mnemonicToSeed(mnemonic);
      final privateKey = ed.newKeyFromSeed(KeyManager.signingSeed(seed));

      final rawEventBytes = base64Decode(rawBytesB64);
      final rawSig = ed.sign(privateKey, Uint8List.fromList(rawEventBytes));

      // Step 3: CESR-encode the raw signature via the stateless /cesr/encode endpoint.
      cesrSignature = await _cesrEncode(base64Encode(rawSig));

      // STEP 4, WHICH EVERY CALLER HAD TO REMEMBER.
      //
      // The route that records this has existed since August and is correct.
      // What was missing is that nothing here called it: each screen was
      // expected to, and the applications people actually ran did not — so
      // every identity they founded published a key history in which nothing
      // had been authorised by anybody. A counterparty
      // checking properly refuses such a log, so the identity works alone and
      // can convince nobody, and nothing said so at any point.
      //
      // It belongs here rather than in a screen for exactly that reason: this
      // is the one place that knows the signature was made, and a step every
      // caller must remember is a step somebody will not.
      //
      // It cannot be sent with the inception itself — the signature is over
      // bytes the engine has not produced when that call is made — so founding
      // is two steps, and this is the second.
      await _attachTheSignature(json['aid'] as String? ?? '', cesrSignature);
    }

    return InceptionResult(
      aid: json['aid'] ?? '',
      publicKey: json['public_key'] ?? '',
      kel: json['kel'] ?? '',
      created: json['created'] ?? DateTime.now().toIso8601String(),
      cesrSignature: cesrSignature,
      rawBytesB64: rawBytesB64,
    );
  }

  /// Hands back the signature over the founding event, which completes it.
  ///
  /// Throws on failure rather than carrying on. An identity whose founding
  /// nobody signed is refused by every counterparty that checks — so finishing
  /// quietly would hand somebody an identity that looks made and cannot be
  /// used with anybody, and the failure would surface weeks later as a stranger
  /// refusing them for no reason they can see.
  Future<void> _attachTheSignature(String aid, String cesrSignature) async {
    if (aid.isEmpty || cesrSignature.isEmpty) {
      throw Exception('this identity was founded and could not be signed, so '
          'nobody would be able to verify it');
    }
    final res = await _client.post(
      Uri.parse('$_baseUrl/api/events/signature'),
      headers: const {'Content-Type': 'application/json'},
      body: jsonEncode({
        'aid': aid,
        // The founding event. This route takes any of them, which is what
        // rotations and interactions need too — a second route that only ever
        // understood the founding would have to be duplicated for each.
        'sequence_number': 0,
        'cesr_signature': cesrSignature,
      }),
    );
    if (res.statusCode != 200) {
      throw Exception('this identity was founded and its signature was refused '
          '(${res.statusCode}): ${res.body}');
    }
  }

  /// Calls POST /api/cesr/encode to wrap a raw base64 signature in CESR '0B...' format.
  Future<String> _cesrEncode(String rawSigB64) async {
    final response = await _client.post(
      Uri.parse('$_baseUrl/api/cesr/encode'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'raw_sig_b64': rawSigB64}),
    );
    if (response.statusCode == 200) {
      final json = jsonDecode(response.body);
      return json['cesr_sig'] as String? ?? '';
    }
    // Non-fatal: return empty string; caller can proceed without CESR sig for now.
    return '';
  }

  @override
  Future<RotationResult> rotateAid({required String name}) async {
    final mnemonic = await SecureKeyStore.loadMnemonic();
    if (mnemonic == null) {
      throw Exception('No identity keys found in secure storage.');
    }

    // The new key is the one founding committed to (index 1), and it signs the
    // rotation; the rotation commits to the key after it (index 2). Both come
    // from KeyManager.signingSeed and nothing hashes them again: a second hash
    // here once made the named key neither the committed one nor the signer.
    final seed = Bip39.mnemonicToSeed(mnemonic);
    final rot1Seed = KeyManager.signingSeed(seed, index: 1);
    final rot1Keys = KeyManager.keyAt(seed, 1);
    final rot2Keys = KeyManager.keyAt(seed, 2);

    // Step 1: Ask the Python driver to create the rotation event.
    final response = await _client.post(
      Uri.parse('$_baseUrl/api/rotation'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'name': name,
        'new_public_key': rot1Keys.publicKeyEncoded,
        'new_next_public_key': rot2Keys.publicKeyEncoded,
      }),
    );

    if (response.statusCode != 200) {
      refusedByTheCore(response, 'Rotation failed');
    }

    final json = jsonDecode(response.body);
    final rawBytesB64 = json['raw_bytes_b64'] as String? ?? '';

    // Step 2: Sign with the pre-rotated key (index 1) and CESR-encode.
    String cesrSig = '';
    if (rawBytesB64.isNotEmpty) {
      final rot1PrivKey = ed.newKeyFromSeed(rot1Seed);
      final rawEventBytes = base64Decode(rawBytesB64);
      final rawSig = ed.sign(rot1PrivKey, Uint8List.fromList(rawEventBytes));
      cesrSig = await _cesrEncode(base64Encode(rawSig));
    }

    return RotationResult(
      aid: json['aid'] ?? '',
      newPublicKey: json['new_public_key'] ?? '',
      kel: json['kel'] ?? '',
      cesrSignature: cesrSig,
    );
  }

  @override
  Future<InteractResult> interactAid({
    required String name,
    List<Map<String, String>> sealData = const [],
  }) async {
    final mnemonic = await SecureKeyStore.loadMnemonic();
    if (mnemonic == null) {
      throw Exception('No identity keys found in secure storage.');
    }

    // Step 1: Create the IXN event via the Python driver.
    final response = await _client.post(
      Uri.parse('$_baseUrl/api/interact'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'name': name, 'data': sealData}),
    );

    if (response.statusCode != 201 && response.statusCode != 200) {
      refusedByTheCore(response, 'IXN failed');
    }

    final json = jsonDecode(response.body);
    final rawBytesB64 = json['raw_bytes_b64'] as String? ?? '';

    // Step 2: Sign IXN event body with current key (index 0) and CESR-encode.
    String cesrSig = '';
    if (rawBytesB64.isNotEmpty) {
      final seed = Bip39.mnemonicToSeed(mnemonic);
      final privateKey = ed.newKeyFromSeed(KeyManager.signingSeed(seed));
      final rawEventBytes = base64Decode(rawBytesB64);
      final rawSig = ed.sign(privateKey, Uint8List.fromList(rawEventBytes));
      cesrSig = await _cesrEncode(base64Encode(rawSig));
    }

    return InteractResult(
      aid: json['aid'] ?? '',
      said: json['said'] ?? '',
      sequenceNumber: json['sequence_number'] as int? ?? 0,
      cesrSignature: cesrSig,
    );
  }

  @override
  Future<SignatureResult> signPayload({
    required String name,
    required List<int> data,
  }) async {
    // Signing is performed locally in Dart using the stored mnemonic.
    // The private key never leaves the device and is never sent to the backend.
    final mnemonic = await SecureKeyStore.loadMnemonic();
    if (mnemonic == null) {
      throw Exception(
          'No identity keys found in secure storage. '
          'Please recreate your identity to restore signing capability.');
    }

    final seed = Bip39.mnemonicToSeed(mnemonic);
    // The key reported is the key that signed. It was derived from the
    // already-hashed seed, hashing it twice, so it named a key that signs
    // nothing.
    final signingKeyPair = KeyManager.generateFromSeed(seed);
    final privateKey = ed.newKeyFromSeed(KeyManager.signingSeed(seed));

    final rawSig = ed.sign(privateKey, Uint8List.fromList(data));
    final rawSigB64 = base64Encode(rawSig);

    // CESR-encode the signature via the stateless Python driver endpoint.
    final cesrSig = await _cesrEncode(rawSigB64);

    return SignatureResult(
      signature: rawSigB64,
      publicKey: signingKeyPair.publicKeyEncoded,
      cesrSignature: cesrSig,
    );
  }

  @override
  Future<String> getCurrentKel({required String name}) async {
    final response = await _client.get(
      Uri.parse('$_baseUrl/api/kel?name=$name'),
    );

    if (response.statusCode == 200) {
      final json = jsonDecode(response.body);
      return json['kel'] ?? '';
    } else {
      throw Exception('Failed to get KEL: ${response.statusCode}');
    }
  }

  @override
  Future<bool> verifySignature({
    required List<int> data,
    required String signature,
    required String publicKey,
  }) async {
    final response = await _client.post(
      Uri.parse('$_baseUrl/api/verify'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'data': base64Encode(data),
        'signature': signature,
        'public_key': publicKey,
      }),
    );

    if (response.statusCode == 200) {
      final json = jsonDecode(response.body);
      return json['valid'] == true;
    } else {
      return false;
    }
  }

  @override
  Future<CredentialIssuanceResult> issueCredential({
    required Map<String, dynamic> claims,
    required String schemaSaid,
    String holderAid = '',
    String name = '',
  }) async {
    // Step 1: Ask the Go backend to format the ACDC and create the IXN anchor.
    final response = await _client.post(
      Uri.parse('$_baseUrl/api/credential/issue'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'claims': claims,
        'schema_said': schemaSaid,
        'holder_aid': holderAid,
      }),
    );

    if (response.statusCode != 201 && response.statusCode != 200) {
      refusedByTheCore(response, 'Credential issuance failed');
    }

    final json = jsonDecode(response.body);
    final ixnRawBytesB64 = json['ixn_raw_bytes_b64'] as String? ?? '';

    // Step 2: Sign the IXN event bytes locally with the current key (index 0).
    // Private key never leaves this device (ADR-014).
    String cesrSig = '';
    if (ixnRawBytesB64.isNotEmpty) {
      final mnemonic = await SecureKeyStore.loadMnemonic();
      if (mnemonic != null) {
        final seed = Bip39.mnemonicToSeed(mnemonic);
        final privateKey = ed.newKeyFromSeed(KeyManager.signingSeed(seed));
        final rawEventBytes = base64Decode(ixnRawBytesB64);
        final rawSig = ed.sign(privateKey, Uint8List.fromList(rawEventBytes));
        cesrSig = await _cesrEncode(base64Encode(rawSig));
      }
    }

    return CredentialIssuanceResult(
      acdcSaid: json['acdc_said'] ?? '',
      acdcJsonB64: json['acdc_json_b64'] ?? '',
      ixnRawBytesB64: ixnRawBytesB64,
      ixnSaid: json['ixn_said'] ?? '',
      sequenceNumber: json['sequence_number'] as int? ?? 0,
      cesrSignature: cesrSig,
    );
  }

  @override
  Future<PresentationResult> presentCredential({
    required String acdcSaid,
    required String holderAid,
    String issuerAid = '',
    String schemaSaid = '',
  }) async {
    // Step 1: Ask the Go backend to build the presentation and compute its SAID.
    final response = await _client.post(
      Uri.parse('$_baseUrl/api/credential/present'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'acdc_said': acdcSaid,
        'holder_aid': holderAid,
        'issuer_aid': issuerAid,
        'schema_said': schemaSaid,
      }),
    );

    if (response.statusCode != 201 && response.statusCode != 200) {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Presentation failed: ${response.statusCode}');
    }

    final json = jsonDecode(response.body);
    final presSaidB64 = json['pres_said_b64'] as String? ?? '';

    // Step 2: Sign the presentation SAID bytes locally with the holder's current
    // key (index 0). This proves possession of the key bound to the holder AID.
    // The holder signs pres_said.encode() — the UTF-8 bytes of the 44-char SAID.
    // Private key never leaves this device (ADR-014).
    String cesrSig = '';
    if (presSaidB64.isNotEmpty) {
      final mnemonic = await SecureKeyStore.loadMnemonic();
      if (mnemonic != null) {
        final seed = Bip39.mnemonicToSeed(mnemonic);
        final privateKey = ed.newKeyFromSeed(KeyManager.signingSeed(seed));
        final saidBytes = base64Decode(presSaidB64);
        final rawSig = ed.sign(privateKey, Uint8List.fromList(saidBytes));
        cesrSig = await _cesrEncode(base64Encode(rawSig));
      }
    }

    return PresentationResult(
      presentationSaid: json['presentation_said'] ?? '',
      presentationJsonB64: json['presentation_json_b64'] ?? '',
      cesrSignature: cesrSig,
    );
  }

  @override
  Future<WitnessReceiptResult> submitWitnessReceipt({
    required String eventSaid,
    required String witnessAid,
    required String cesrSignature,
  }) async {
    final response = await _client.post(
      Uri.parse('$_baseUrl/api/receipt/submit'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'event_said': eventSaid,
        'witness_aid': witnessAid,
        'cesr_signature': cesrSignature,
      }),
    );

    if (response.statusCode == 200) {
      final json = jsonDecode(response.body);
      return WitnessReceiptResult(
        accepted: json['accepted'] == true,
        thresholdMet: json['threshold_met'] == true,
        receiptCount: json['receipt_count'] as int? ?? 0,
        errors: List<String>.from(json['errors'] ?? []),
      );
    } else {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Receipt submission failed: ${response.statusCode}');
    }
  }

  @override
  Future<KerlEntry> getKERL({
    required String eventSaid,
    int threshold = 0,
  }) async {
    final response = await _client.get(
      Uri.parse('$_baseUrl/api/kerl?event_said=$eventSaid&threshold=$threshold'),
    );

    if (response.statusCode == 200) {
      final json = jsonDecode(response.body);
      return KerlEntry(
        eventSaid: json['event_said'] ?? '',
        receipts: List<Map<String, dynamic>>.from(
          (json['receipts'] as List? ?? []).map((r) => Map<String, dynamic>.from(r)),
        ),
        receiptCount: json['receipt_count'] as int? ?? 0,
        thresholdMet: json['threshold_met'] == true,
      );
    } else {
      throw Exception('Failed to get KERL: ${response.statusCode}');
    }
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
      Uri.parse('$_baseUrl/api/credential/verify'),
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
      final json = jsonDecode(response.body);
      return VerificationResult(
        verified: json['verified'] == true,
        checks: (json['checks'] as Map<String, dynamic>?) ?? {},
        errors: List<String>.from(json['errors'] ?? []),
        acdcSaid: json['acdc_said'] ?? '',
      );
    } else {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Credential verification failed: ${response.statusCode}');
    }
  }

  @override
  void dispose() {
    _client.close();
  }
}

/// The name this class had when it was only used on desktop.
@Deprecated('Use LocalCoreKeriService — it serves mobile too')
typedef DesktopOnDeviceKeriService = LocalCoreKeriService;
