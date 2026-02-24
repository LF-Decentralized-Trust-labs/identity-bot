import 'dart:convert';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'core_service.dart';

class MobileCoreService {
  static const _channel = MethodChannel('com.identityagent/mobilecore');
  static const int defaultPort = 8642;

  int _port = defaultPort;
  bool _started = false;
  CoreService? _coreClient;

  int get port => _port;
  bool get isStarted => _started;

  String get baseUrl => 'http://127.0.0.1:$_port';

  CoreService get coreClient {
    _coreClient ??= CoreService(baseUrl: baseUrl);
    return _coreClient!;
  }

  Future<void> startCore({String? dataDir, int? port}) async {
    if (_started) return;

    try {
      final result = await _channel.invokeMethod('startServer', {
        if (dataDir != null) 'dataDir': dataDir,
        'port': port ?? defaultPort,
      });

      if (result is Map) {
        _port = result['port'] ?? defaultPort;
      }
      _started = true;
      _coreClient = CoreService(baseUrl: baseUrl);
    } on PlatformException catch (e) {
      throw Exception('Failed to start Go Core: ${e.message}');
    }
  }

  Future<void> stopCore() async {
    if (!_started) return;

    try {
      await _channel.invokeMethod('stopServer');
      _started = false;
      _coreClient?.dispose();
      _coreClient = null;
    } on PlatformException catch (e) {
      throw Exception('Failed to stop Go Core: ${e.message}');
    }
  }

  Future<bool> isRunning() async {
    try {
      final result = await _channel.invokeMethod('isRunning');
      return result == true;
    } catch (_) {
      return false;
    }
  }

  Future<String?> getHealth() async {
    try {
      final result = await _channel.invokeMethod('getHealth');
      return result as String?;
    } on PlatformException catch (e) {
      throw Exception('Health check failed: ${e.message}');
    }
  }

  Future<int> getPort() async {
    try {
      final result = await _channel.invokeMethod('getPort');
      return result as int? ?? 0;
    } catch (_) {
      return 0;
    }
  }

  Future<String> getDataDir() async {
    try {
      final result = await _channel.invokeMethod('getDataDir');
      return result as String? ?? '';
    } catch (_) {
      return '';
    }
  }

  Future<bool> waitForReady({Duration timeout = const Duration(seconds: 10)}) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      try {
        final response = await http.get(
          Uri.parse('$baseUrl/api/health'),
        ).timeout(const Duration(seconds: 2));
        if (response.statusCode == 200) {
          return true;
        }
      } catch (_) {}
      await Future.delayed(const Duration(milliseconds: 200));
    }
    return false;
  }

  Future<void> storeIdentity({
    required String aid,
    required String publicKey,
    String? nextKeyDigest,
    int eventCount = 1,
  }) async {
    final response = await http.post(
      Uri.parse('$baseUrl/api/store/identity'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'aid': aid,
        'public_key': publicKey,
        if (nextKeyDigest != null) 'next_key_digest': nextKeyDigest,
        'event_count': eventCount,
      }),
    );

    if (response.statusCode != 201) {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Store identity failed: ${response.statusCode}');
    }
  }

  Future<void> storeEvent({
    required String aid,
    required String eventType,
    required int sequenceNumber,
    String? eventJson,
    String? publicKey,
    String? nextKeyDigest,
  }) async {
    final response = await http.post(
      Uri.parse('$baseUrl/api/store/event'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'aid': aid,
        'event_type': eventType,
        'sequence_number': sequenceNumber,
        if (eventJson != null) 'event_json': eventJson,
        if (publicKey != null) 'public_key': publicKey,
        if (nextKeyDigest != null) 'next_key_digest': nextKeyDigest,
      }),
    );

    if (response.statusCode != 201) {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Store event failed: ${response.statusCode}');
    }
  }

  void dispose() {
    _coreClient?.dispose();
    _coreClient = null;
  }
}
