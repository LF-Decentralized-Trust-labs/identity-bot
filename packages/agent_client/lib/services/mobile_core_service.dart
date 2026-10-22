import 'dart:convert';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'backend_process_service.dart';
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

  /// What the app's native side is given to start the core. The relays come
  /// from the same [BackendProcessService.environmentDefaults] a desktop app
  /// sets, so an app names its relays once for every platform; the native side
  /// passes them to `mobilecore.DeclareRelays` before `StartServer`.
  static Map<String, Object> startArguments({String? dataDir, int? port}) {
    final defaults = BackendProcessService.environmentDefaults;
    final privateRelay = defaults['RELAY_BASE_URL'] ?? '';
    final publicRelay = defaults['PUBLIC_RELAY_BASE_URL'] ?? '';
    return {
      if (dataDir != null) 'dataDir': dataDir,
      'port': port ?? defaultPort,
      if (privateRelay.isNotEmpty) 'privateRelay': privateRelay,
      if (publicRelay.isNotEmpty) 'publicRelay': publicRelay,
    };
  }

  Future<void> startCore({String? dataDir, int? port}) async {
    if (_started) return;

    try {
      final result = await _channel.invokeMethod(
          'startServer', startArguments(dataDir: dataDir, port: port));

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

  /// Whether the core is ACTUALLY answering on its port right now.
  ///
  /// Checked over HTTP rather than [isRunning], because the signal that matters
  /// after a long iOS suspension is the socket, not the native pointer: the OS
  /// tears down the listener while the Go side keeps a non-nil server, so
  /// [isRunning] reports true while every request is refused.
  Future<bool> isHealthy() async {
    // Two attempts, because the first request after a cold thaw can miss the
    // window while the just-unfrozen process finishes its first scheduling —
    // declaring the core dead on that single slow response would stop and
    // restart a core that was about to answer. A busy core still answers the
    // lightweight health route well within the timeout, so this does not mask a
    // genuinely dead one for longer than ~2.3s.
    for (var attempt = 0; attempt < 2; attempt++) {
      try {
        final r = await http
            .get(Uri.parse('$baseUrl/api/health'))
            .timeout(const Duration(seconds: 2));
        if (r.statusCode == 200) return true;
      } catch (_) {
        // refused / timed out — try once more before giving up
      }
      if (attempt == 0) {
        await Future<void>.delayed(const Duration(milliseconds: 300));
      }
    }
    return false;
  }

  /// Returns to a state where [startCore] will actually start the core again,
  /// even when the native stop fails because the listener is already gone.
  ///
  /// [stopCore] leaves [_started] true on a failed stop, and [startCore]
  /// short-circuits on [_started]; after a long suspension the listener is dead
  /// while the flag says started, so a plain restart would be a silent no-op.
  /// This drops the native server pointer (best effort) and clears the local
  /// state unconditionally, so the next [startCore] binds a fresh listener.
  Future<void> forceStopped() async {
    try {
      await _channel.invokeMethod('stopServer');
    } catch (_) {
      // The listener may already be gone; the point is only to get the native
      // side to drop its server so a fresh start can bind the port.
    }
    _started = false;
    _coreClient?.dispose();
    _coreClient = null;
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

  Future<bool> waitForReady(
      {Duration timeout = const Duration(seconds: 10)}) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      try {
        final response = await http
            .get(
              Uri.parse('$baseUrl/api/health'),
            )
            .timeout(const Duration(seconds: 2));
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
      throw Exception(
          body['error'] ?? 'Store identity failed: ${response.statusCode}');
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
      throw Exception(
          body['error'] ?? 'Store event failed: ${response.statusCode}');
    }
  }

  void dispose() {
    _coreClient?.dispose();
    _coreClient = null;
  }
}
