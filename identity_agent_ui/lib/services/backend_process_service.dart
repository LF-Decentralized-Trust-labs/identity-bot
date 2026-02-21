import 'dart:io';
import 'package:flutter/foundation.dart';

class BackendProcessService {
  static BackendProcessService? _instance;
  Process? _backendProcess;
  bool _isRunning = false;
  String? _backendPath;

  BackendProcessService._();

  static BackendProcessService get instance {
    _instance ??= BackendProcessService._();
    return _instance!;
  }

  bool get isRunning => _isRunning;

  static bool get isDesktopPlatform {
    if (kIsWeb) return false;
    try {
      return Platform.isWindows || Platform.isMacOS || Platform.isLinux;
    } catch (_) {
      return false;
    }
  }

  String? _findBackendBinary() {
    final exePath = Platform.resolvedExecutable;
    final exeDir = File(exePath).parent.path;

    final candidates = <String>[];

    if (Platform.isWindows) {
      candidates.addAll([
        '$exeDir${Platform.pathSeparator}backend${Platform.pathSeparator}identity-agent-core.exe',
        '$exeDir${Platform.pathSeparator}identity-agent-core.exe',
      ]);
    } else if (Platform.isMacOS) {
      final appDir = File(exePath).parent.parent.path;
      candidates.addAll([
        '$appDir${Platform.pathSeparator}Resources${Platform.pathSeparator}backend${Platform.pathSeparator}identity-agent-core',
        '$exeDir${Platform.pathSeparator}backend${Platform.pathSeparator}identity-agent-core',
      ]);
    } else {
      candidates.addAll([
        '$exeDir${Platform.pathSeparator}backend${Platform.pathSeparator}identity-agent-core',
        '$exeDir${Platform.pathSeparator}identity-agent-core',
      ]);
    }

    for (final path in candidates) {
      if (File(path).existsSync()) {
        debugPrint('[BackendProcess] Found binary at: $path');
        return path;
      }
    }

    debugPrint('[BackendProcess] No backend binary found. Searched:');
    for (final path in candidates) {
      debugPrint('  - $path');
    }
    return null;
  }

  Future<bool> start() async {
    if (!isDesktopPlatform) {
      debugPrint('[BackendProcess] Not a desktop platform, skipping');
      return false;
    }

    if (_isRunning && _backendProcess != null) {
      debugPrint('[BackendProcess] Already running (PID: ${_backendProcess!.pid})');
      return true;
    }

    _backendPath = _findBackendBinary();
    if (_backendPath == null) {
      debugPrint('[BackendProcess] Backend binary not found — running in development mode?');
      return false;
    }

    try {
      final backendDir = File(_backendPath!).parent.path;

      final env = Map<String, String>.from(Platform.environment);
      env['PORT'] = '5000';
      env['HOST'] = '0.0.0.0';

      debugPrint('[BackendProcess] Starting: $_backendPath');
      debugPrint('[BackendProcess] Working dir: $backendDir');

      _backendProcess = await Process.start(
        _backendPath!,
        [],
        workingDirectory: backendDir,
        environment: env,
      );

      _isRunning = true;
      debugPrint('[BackendProcess] Started (PID: ${_backendProcess!.pid})');

      _backendProcess!.stdout.transform(const SystemEncoding().decoder).listen(
        (data) => debugPrint('[Backend] $data'),
      );
      _backendProcess!.stderr.transform(const SystemEncoding().decoder).listen(
        (data) => debugPrint('[Backend:err] $data'),
      );

      _backendProcess!.exitCode.then((code) {
        debugPrint('[BackendProcess] Exited with code: $code');
        _isRunning = false;
        _backendProcess = null;
      });

      await _waitForHealthy();
      return true;
    } catch (e) {
      debugPrint('[BackendProcess] Failed to start: $e');
      _isRunning = false;
      return false;
    }
  }

  Future<void> _waitForHealthy() async {
    final client = HttpClient();
    client.connectionTimeout = const Duration(seconds: 2);

    for (int i = 0; i < 30; i++) {
      try {
        final request = await client.getUrl(
          Uri.parse('http://localhost:5000/api/health'),
        );
        final response = await request.close();
        if (response.statusCode == 200) {
          debugPrint('[BackendProcess] Backend is healthy (attempt ${i + 1})');
          client.close();
          return;
        }
      } catch (_) {}
      await Future.delayed(const Duration(milliseconds: 500));
    }
    client.close();
    debugPrint('[BackendProcess] Health check timed out after 15s');
  }

  Future<void> stop() async {
    if (_backendProcess != null) {
      debugPrint('[BackendProcess] Stopping (PID: ${_backendProcess!.pid})');
      _backendProcess!.kill(ProcessSignal.sigterm);
      try {
        await _backendProcess!.exitCode.timeout(const Duration(seconds: 5));
      } catch (_) {
        _backendProcess!.kill(ProcessSignal.sigkill);
      }
      _backendProcess = null;
      _isRunning = false;
    }
  }
}
