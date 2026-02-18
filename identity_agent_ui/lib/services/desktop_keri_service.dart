import 'dart:convert';
import 'package:http/http.dart' as http;
import '../config/agent_config.dart';
import 'keri_service.dart';

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
    final response = await _client.post(
      Uri.parse('$_baseUrl/api/inception'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'name': name,
        'code': code,
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
    final response = await _client.post(
      Uri.parse('$_baseUrl/api/sign'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'name': name,
        'data': base64Encode(data),
      }),
    );

    if (response.statusCode == 200) {
      final json = jsonDecode(response.body);
      return SignatureResult(
        signature: json['signature'] ?? '',
        publicKey: json['public_key'] ?? '',
      );
    } else {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Signing failed: ${response.statusCode}');
    }
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
