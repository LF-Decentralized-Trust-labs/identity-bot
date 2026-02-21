import 'dart:io';
import 'package:flutter/foundation.dart';

class BackendProcessService {
  static BackendProcessService? _instance;
  Process? _backendProcess;
  bool _isRunning = false;
  String? _backendPath;
  String? _startupError;

  BackendProcessService._();

  static BackendProcessService get instance {
    _instance ??= BackendProcessService._();
    return _instance!;
  }

  bool get isRunning => _isRunning;
  String? get startupError => _startupError;

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
    final sep = Platform.pathSeparator;

    final candidates = <String>[];

    if (Platform.isWindows) {
      candidates.addAll([
        '$exeDir${sep}backend${sep}identity-agent-core.exe',
        '$exeDir${sep}identity-agent-core.exe',
      ]);
    } else if (Platform.isMacOS) {
      final appDir = File(exePath).parent.parent.path;
      candidates.addAll([
        '$appDir${sep}Resources${sep}backend${sep}identity-agent-core',
        '$exeDir${sep}backend${sep}identity-agent-core',
      ]);
    } else {
      candidates.addAll([
        '$exeDir${sep}backend${sep}identity-agent-core',
        '$exeDir${sep}identity-agent-core',
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

  String? _findKeriDriverScript(String backendDir) {
    final sep = Platform.pathSeparator;
    final candidates = [
      '$backendDir${sep}keri-driver${sep}server.py',
      '$backendDir${sep}drivers${sep}keri-core${sep}server.py',
    ];

    for (final path in candidates) {
      if (File(path).existsSync()) {
        debugPrint('[BackendProcess] Found KERI driver at: $path');
        return path;
      }
    }

    debugPrint('[BackendProcess] KERI driver script not found. Searched:');
    for (final path in candidates) {
      debugPrint('  - $path');
    }
    return null;
  }

  Future<String?> _findPythonBinary() async {
    final candidates = Platform.isWindows
        ? ['python', 'python3', 'py']
        : ['python3', 'python'];

    for (final bin in candidates) {
      try {
        final result = await Process.run(bin, ['--version']);
        if (result.exitCode == 0) {
          final version = (result.stdout as String).trim();
          debugPrint('[BackendProcess] Found Python: $bin ($version)');
          return bin;
        }
      } catch (_) {}
    }

    debugPrint('[BackendProcess] Python not found on PATH');
    return null;
  }

  Future<bool> _checkPythonDeps(String pythonBin) async {
    try {
      final result = await Process.run(
        pythonBin,
        ['-c', 'import flask; import keri'],
      );
      if (result.exitCode == 0) {
        debugPrint('[BackendProcess] Python deps (flask, keri) available');
        return true;
      }
      debugPrint('[BackendProcess] Missing Python deps: ${result.stderr}');
      return false;
    } catch (e) {
      debugPrint('[BackendProcess] Python dep check failed: $e');
      return false;
    }
  }

  Future<bool> _installPythonDeps(String pythonBin, String backendDir) async {
    debugPrint('[BackendProcess] Installing Python dependencies...');
    try {
      final sep = Platform.pathSeparator;
      final reqCandidates = [
        '$backendDir${sep}keri-driver${sep}requirements.txt',
        '$backendDir${sep}drivers${sep}keri-core${sep}requirements.txt',
      ];

      for (final reqPath in reqCandidates) {
        if (File(reqPath).existsSync()) {
          debugPrint('[BackendProcess] Installing from: $reqPath');
          final result = await Process.run(
            pythonBin,
            ['-m', 'pip', 'install', '-r', reqPath],
            environment: Platform.environment,
          );
          if (result.exitCode == 0) {
            debugPrint('[BackendProcess] Python dependencies installed from requirements.txt');
            return true;
          }
          debugPrint('[BackendProcess] pip install -r failed: ${result.stderr}');
        }
      }

      debugPrint('[BackendProcess] Falling back to direct pip install...');
      var result = await Process.run(
        pythonBin,
        ['-m', 'pip', 'install', 'flask', 'keri==1.1.17'],
        environment: Platform.environment,
      );

      if (result.exitCode == 0) {
        debugPrint('[BackendProcess] Python dependencies installed successfully');
        return true;
      }

      debugPrint('[BackendProcess] pip install failed: ${result.stderr}');
      return false;
    } catch (e) {
      debugPrint('[BackendProcess] pip install error: $e');
      return false;
    }
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

    _startupError = null;

    _backendPath = _findBackendBinary();
    if (_backendPath == null) {
      debugPrint('[BackendProcess] Backend binary not found — running in development mode?');
      return false;
    }

    final backendDir = File(_backendPath!).parent.path;

    final pythonBin = await _findPythonBinary();
    if (pythonBin == null) {
      _startupError =
          'Python 3 is required but was not found on this computer. '
          'Please install Python 3.10+ from python.org and restart the app.';
      return false;
    }

    final depsOk = await _checkPythonDeps(pythonBin);
    if (!depsOk) {
      debugPrint('[BackendProcess] Attempting auto-install of Python deps...');
      final installed = await _installPythonDeps(pythonBin, backendDir);
      if (!installed) {
        _startupError =
            'Required Python packages (flask, keri) could not be installed. '
            'Please run: $pythonBin -m pip install flask keri==1.1.17';
        return false;
      }
    }

    final keriScript = _findKeriDriverScript(backendDir);

    try {
      final env = Map<String, String>.from(Platform.environment);
      env['PORT'] = '5000';
      env['HOST'] = '0.0.0.0';
      env['KERI_DRIVER_PYTHON'] = pythonBin;
      if (keriScript != null) {
        env['KERI_DRIVER_SCRIPT'] = keriScript;
      }

      debugPrint('[BackendProcess] Starting: $_backendPath');
      debugPrint('[BackendProcess] Working dir: $backendDir');
      debugPrint('[BackendProcess] Python: $pythonBin');
      if (keriScript != null) {
        debugPrint('[BackendProcess] KERI driver: $keriScript');
      }

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
        if (code != 0) {
          _startupError = 'Backend process exited unexpectedly (code $code). '
              'Check that Python and KERI dependencies are properly installed.';
        }
      });

      final healthy = await _waitForHealthy();
      if (!healthy) {
        _startupError ??=
            'Backend started but did not become healthy within 15 seconds. '
            'The Python KERI driver may have failed to start.';
        return false;
      }
      return true;
    } catch (e) {
      debugPrint('[BackendProcess] Failed to start: $e');
      _startupError = 'Failed to start backend: $e';
      _isRunning = false;
      return false;
    }
  }

  Future<bool> _waitForHealthy() async {
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
          return true;
        }
      } catch (_) {}
      await Future.delayed(const Duration(milliseconds: 500));
    }
    client.close();
    debugPrint('[BackendProcess] Health check timed out after 15s');
    return false;
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
