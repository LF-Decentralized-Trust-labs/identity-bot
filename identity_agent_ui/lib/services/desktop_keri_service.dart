import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;
import '../config/agent_config.dart';
import '../crypto/bip39.dart';
import '../crypto/keys.dart';
import 'keri_service.dart';
import 'secure_key_store.dart';

class DesktopKeriService extends KeriService {
  final String _baseUrl;
  final http.Client _client;

  DesktopKeriService({String? baseUrl})
      : _baseUrl = baseUrl ?? AgentConfig.coreBaseUrl,
        _client = http.Client();

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
      final seedHash = sha256.convert(seed.sublist(0, 32));
      final privateSeed = Uint8List.fromList(seedHash.bytes);
      final privateKey = ed.newKeyFromSeed(privateSeed);

      final rawEventBytes = base64Decode(rawBytesB64);
      final rawSig = ed.sign(privateKey, Uint8List.fromList(rawEventBytes));

      // Step 3: CESR-encode the raw signature via the stateless /cesr/encode endpoint.
      cesrSignature = await _cesrEncode(base64Encode(rawSig));
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

    // Derive the pre-rotated key (index 1) and the next-next key (index 2).
    // Rotation is signed with the PRE-ROTATED key (index 1), not the original key.
    final seed = Bip39.mnemonicToSeed(mnemonic);
    final seedBytes = Uint8List.fromList(seed.sublist(0, 32));

    // Index 1: the key that was committed as pre-rotation at inception
    final rot1Hash = sha256.convert([...seedBytes, 0x01]);
    final rot1Seed = Uint8List.fromList(rot1Hash.bytes);
    final rot1Keys = KeyManager.generateFromSeed(rot1Seed);

    // Index 2: the new pre-rotation to commit
    final rot2Hash = sha256.convert([...seedBytes, 0x02]);
    final rot2Keys = KeyManager.generateFromSeed(Uint8List.fromList(rot2Hash.bytes));

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
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Rotation failed: ${response.statusCode}');
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
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'IXN failed: ${response.statusCode}');
    }

    final json = jsonDecode(response.body);
    final rawBytesB64 = json['raw_bytes_b64'] as String? ?? '';

    // Step 2: Sign IXN event body with current key (index 0) and CESR-encode.
    String cesrSig = '';
    if (rawBytesB64.isNotEmpty) {
      final seed = Bip39.mnemonicToSeed(mnemonic);
      final seedHash = sha256.convert(seed.sublist(0, 32));
      final privateSeed = Uint8List.fromList(seedHash.bytes);
      final privateKey = ed.newKeyFromSeed(privateSeed);
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
    final seedHash = sha256.convert(seed.sublist(0, 32));
    final privateSeed = Uint8List.fromList(seedHash.bytes);
    final privateKey = ed.newKeyFromSeed(privateSeed);

    final rawSig = ed.sign(privateKey, Uint8List.fromList(data));
    final signingKeyPair = KeyManager.generateFromSeed(privateSeed);
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
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Credential issuance failed: ${response.statusCode}');
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
        final seedHash = sha256.convert(seed.sublist(0, 32));
        final privateSeed = Uint8List.fromList(seedHash.bytes);
        final privateKey = ed.newKeyFromSeed(privateSeed);
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
  void dispose() {
    _client.close();
  }
}
