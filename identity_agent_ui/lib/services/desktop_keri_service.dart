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

    final response = await _client.post(
      Uri.parse('$_baseUrl/api/inception'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'public_key': keys.signing.publicKeyEncoded,
        'next_public_key': keys.next.publicKeyEncoded,
      }),
    );

    if (response.statusCode == 201 || response.statusCode == 200) {
      final json = jsonDecode(response.body);
      return InceptionResult(
        aid: json['aid'] ?? '',
        publicKey: json['public_key'] ?? '',
        kel: json['kel'] ?? '',
        created: json['created'] ?? DateTime.now().toIso8601String(),
      );
    } else {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Inception failed: ${response.statusCode}');
    }
  }

  @override
  Future<RotationResult> rotateAid({required String name}) async {
    final response = await _client.post(
      Uri.parse('$_baseUrl/api/rotation'),
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
    } else {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Rotation failed: ${response.statusCode}');
    }
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

    final signature = ed.sign(privateKey, Uint8List.fromList(data));
    final signingKeyPair = KeyManager.generateFromSeed(privateSeed);

    return SignatureResult(
      signature: base64Encode(signature),
      publicKey: signingKeyPair.publicKeyEncoded,
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
  void dispose() {
    _client.close();
  }
}
