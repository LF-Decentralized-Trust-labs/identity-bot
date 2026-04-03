import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:identity_agent_ui/config/agent_config.dart';

class PortConflictInfo {
  final String pid;
  final String processName;
  final int port;

  PortConflictInfo({required this.pid, required this.processName, required this.port});

  bool get isIdentityAgent =>
      processName.toLowerCase().contains('identity-agent') ||
      processName.toLowerCase().contains('identity_agent');
}

class BackendProcessService {
  static BackendProcessService? _instance;
  Process? _backendProcess;
  bool _isRunning = false;
  String? _backendPath;
  String? _startupError;
  PortConflictInfo? _portConflict;
  final List<String> _backendOutput = [];
  static const int _maxOutputLines = 200;

  BackendProcessService._();

  static BackendProcessService get instance {
    _instance ??= BackendProcessService._();
    return _instance!;
  }

  bool get isRunning => _isRunning;
  String? get startupError => _startupError;
  String get diagnosticOutput => _backendOutput.join('\n');
  PortConflictInfo? get portConflict => _portConflict;

  static bool get isDesktopPlatform {
    if (kIsWeb) return false;
    try {
      return Platform.isWindows || Platform.isMacOS || Platform.isLinux;
    } catch (_) {
      return false;
    }
  }

  void _appendOutput(String line) {
    _backendOutput.add(line);
    if (_backendOutput.length > _maxOutputLines) {
      _backendOutput.removeAt(0);
    }
  }

  Future<void> _writeDiagnosticLog(String backendDir) async {
    try {
      final exeDir = File(Platform.resolvedExecutable).parent.path;
      final logFile = File('$exeDir${Platform.pathSeparator}backend-startup.log');
      final content = StringBuffer();
      content.writeln('=== Identity Agent Backend Diagnostic Log ===');
      content.writeln('Timestamp: ${DateTime.now().toIso8601String()}');
      content.writeln('Platform: ${Platform.operatingSystem} ${Platform.operatingSystemVersion}');
      content.writeln('Backend path: $_backendPath');
      content.writeln('Working directory: $backendDir');
      content.writeln('');
      content.writeln('=== Backend Output ===');
      for (final line in _backendOutput) {
        content.writeln(line);
      }
      content.writeln('');
      content.writeln('=== Startup Error ===');
      content.writeln(_startupError ?? 'none');
      await logFile.writeAsString(content.toString());
      debugPrint('[BackendProcess] Diagnostic log written to: ${logFile.path}');
    } catch (e) {
      debugPrint('[BackendProcess] Failed to write diagnostic log: $e');
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

  String? _findBundledPython(String backendDir) {
    final sep = Platform.pathSeparator;

    if (Platform.isWindows) {
      final candidates = [
        '$backendDir${sep}python${sep}python.exe',
        '$backendDir${sep}python${sep}python3.exe',
      ];
      for (final path in candidates) {
        if (File(path).existsSync()) {
          debugPrint('[BackendProcess] Found bundled Python at: $path');
          return path;
        }
      }
    }

    return null;
  }

  String? _findBundledPythonPackages(String backendDir) {
    final sep = Platform.pathSeparator;
    final pkgDir = '$backendDir${sep}python-packages';
    if (Directory(pkgDir).existsSync()) {
      debugPrint('[BackendProcess] Found bundled Python packages at: $pkgDir');
      return pkgDir;
    }
    return null;
  }

  Future<String?> _findPythonBinary(String backendDir) async {
    final bundled = _findBundledPython(backendDir);
    if (bundled != null) {
      return bundled;
    }

    debugPrint('[BackendProcess] No bundled Python — searching system PATH...');
    final candidates = Platform.isWindows
        ? ['python', 'python3', 'py']
        : ['python3', 'python'];

    for (final bin in candidates) {
      try {
        final result = await Process.run(bin, ['--version']);
        if (result.exitCode == 0) {
          final version = (result.stdout as String).trim();
          debugPrint('[BackendProcess] Found system Python: $bin ($version)');
          _appendOutput('[startup] Found system Python: $bin ($version)');
          return bin;
        }
      } catch (_) {}
    }

    debugPrint('[BackendProcess] Python not found anywhere');
    return null;
  }

  bool _isBundledPython(String pythonBin, String backendDir) {
    return pythonBin.startsWith(backendDir);
  }

  Future<bool> _checkPythonDeps(String pythonBin) async {
    try {
      final result = await Process.run(
        pythonBin,
        ['-c', 'import flask; import keri'],
      );
      if (result.exitCode == 0) {
        debugPrint('[BackendProcess] Python deps (flask, keri) available');
        _appendOutput('[startup] Python deps (flask, keri) verified OK');
        return true;
      }
      debugPrint('[BackendProcess] Missing Python deps: ${result.stderr}');
      _appendOutput('[startup] Missing Python deps: ${result.stderr}');
      return false;
    } catch (e) {
      debugPrint('[BackendProcess] Python dep check failed: $e');
      _appendOutput('[startup] Python dep check failed: $e');
      return false;
    }
  }

  Future<bool> _installPythonDeps(String pythonBin, String backendDir) async {
    debugPrint('[BackendProcess] Installing Python dependencies...');
    _appendOutput('[startup] Installing Python dependencies...');
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
            _appendOutput('[startup] Python deps installed from requirements.txt');
            return true;
          }
          debugPrint('[BackendProcess] pip install -r failed: ${result.stderr}');
          _appendOutput('[startup] pip install -r failed: ${result.stderr}');
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
        _appendOutput('[startup] Python deps installed successfully');
        return true;
      }

      debugPrint('[BackendProcess] pip install failed: ${result.stderr}');
      _appendOutput('[startup] pip install failed: ${result.stderr}');
      return false;
    } catch (e) {
      debugPrint('[BackendProcess] pip install error: $e');
      _appendOutput('[startup] pip install error: $e');
      return false;
    }
  }

  Future<PortConflictInfo?> checkPortConflict(int port) async {
    debugPrint('[BackendProcess] Checking for existing processes on port $port...');

    try {
      if (Platform.isWindows) {
        final result = await Process.run('netstat', ['-ano', '-p', 'TCP']);
        if (result.exitCode != 0) return null;

        final portPattern = RegExp(
          r'^\s*TCP\s+\S+:(\d+)\s+\S+\s+LISTENING\s+(\d+)',
          caseSensitive: false,
        );
        for (final line in (result.stdout as String).split('\n')) {
          final match = portPattern.firstMatch(line);
          if (match != null) {
            final foundPort = int.tryParse(match.group(1) ?? '');
            final pid = match.group(2) ?? '';
            if (foundPort == port && pid.isNotEmpty && pid != '0') {
              String processName = 'unknown';
              try {
                final taskResult = await Process.run(
                  'tasklist',
                  ['/FI', 'PID eq $pid', '/FO', 'CSV', '/NH'],
                );
                if (taskResult.exitCode == 0) {
                  final csv = (taskResult.stdout as String).trim();
                  if (csv.isNotEmpty && csv.startsWith('"')) {
                    processName = csv.split(',')[0].replaceAll('"', '');
                  }
                }
              } catch (_) {}
              debugPrint('[BackendProcess] Port $port in use by PID $pid ($processName)');
              return PortConflictInfo(pid: pid, processName: processName, port: port);
            }
          }
        }
      } else {
        final result = await Process.run('lsof', ['-ti', ':$port']);
        if (result.exitCode == 0) {
          final pid = (result.stdout as String).trim().split('\n').first;
          if (pid.isNotEmpty && int.tryParse(pid) != null) {
            String processName = 'unknown';
            try {
              final psResult = await Process.run('ps', ['-p', pid, '-o', 'comm=']);
              if (psResult.exitCode == 0) {
                processName = (psResult.stdout as String).trim();
              }
            } catch (_) {}
            debugPrint('[BackendProcess] Port $port in use by PID $pid ($processName)');
            return PortConflictInfo(pid: pid, processName: processName, port: port);
          }
        }
      }
    } catch (e) {
      debugPrint('[BackendProcess] Port check failed (non-fatal): $e');
    }
    return null;
  }

  Future<bool> killProcessOnPort(PortConflictInfo conflict) async {
    debugPrint('[BackendProcess] Killing PID ${conflict.pid} on port ${conflict.port}...');
    _appendOutput('[startup] User confirmed — killing PID ${conflict.pid} (${conflict.processName})');

    try {
      if (Platform.isWindows) {
        final result = await Process.run('taskkill', ['/F', '/PID', conflict.pid]);
        if (result.exitCode != 0) {
          _appendOutput('[startup] taskkill failed: ${result.stderr}');
          return false;
        }
      } else {
        final result = await Process.run('kill', ['-9', conflict.pid]);
        if (result.exitCode != 0) {
          _appendOutput('[startup] kill failed: ${result.stderr}');
          return false;
        }
      }
      await Future.delayed(const Duration(seconds: 1));
      return true;
    } catch (e) {
      debugPrint('[BackendProcess] Kill failed: $e');
      _appendOutput('[startup] Kill failed: $e');
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
    _backendOutput.clear();
    _appendOutput('[startup] ${DateTime.now().toIso8601String()}');
    _appendOutput('[startup] Platform: ${Platform.operatingSystem} ${Platform.operatingSystemVersion}');

    _backendPath = _findBackendBinary();
    if (_backendPath == null) {
      _startupError =
          'Backend binary (identity-agent-core) was not found in the application bundle. '
          'The app may not have been packaged correctly. '
          'If running in development mode, start the backend manually.';
      debugPrint('[BackendProcess] Backend binary not found — $_startupError');
      _appendOutput('[startup] Backend binary not found');
      final exeDir = File(Platform.resolvedExecutable).parent.path;
      await _writeDiagnosticLog(exeDir);
      return false;
    }

    _appendOutput('[startup] Backend binary: $_backendPath');

    final backendDir = File(_backendPath!).parent.path;

    _portConflict = null;
    final defaultPort = AgentConfig.defaultDesktopPort;
    final conflict = await checkPortConflict(defaultPort);
    if (conflict != null) {
      if (conflict.isIdentityAgent) {
        _appendOutput('[startup] Found stale Identity Agent process (PID ${conflict.pid}) — auto-killing');
        await killProcessOnPort(conflict);
      } else {
        // Don't block startup — the Go backend will auto-select a fallback port
        _appendOutput('[startup] Port $defaultPort is in use by ${conflict.processName} (PID ${conflict.pid}) — backend will auto-select fallback port');
      }
    }

    final pythonBin = await _findPythonBinary(backendDir);
    if (pythonBin == null) {
      _startupError =
          'Python was not found in the application bundle or on this computer. '
          'The application may not have been packaged correctly.\n\n'
          'As a workaround, install Python 3.10+ from python.org and restart.';
      await _writeDiagnosticLog(backendDir);
      return false;
    }

    _appendOutput('[startup] Python: $pythonBin');

    final isBundled = _isBundledPython(pythonBin, backendDir);
    final bundledPkgDir = _findBundledPythonPackages(backendDir);
    final hasBundledDeps = isBundled || bundledPkgDir != null;

    if (hasBundledDeps) {
      debugPrint('[BackendProcess] Using bundled dependencies — skipping dependency checks');
      _appendOutput('[startup] Using bundled dependencies');
    } else {
      final depsOk = await _checkPythonDeps(pythonBin);
      if (!depsOk) {
        debugPrint('[BackendProcess] Attempting auto-install of Python deps...');
        final installed = await _installPythonDeps(pythonBin, backendDir);
        if (!installed) {
          _startupError =
              'Required Python packages (flask, keri) could not be installed. '
              'Please run: $pythonBin -m pip install flask keri==1.1.17';
          await _writeDiagnosticLog(backendDir);
          return false;
        }
      }
    }

    final keriScript = _findKeriDriverScript(backendDir);
    _appendOutput('[startup] KERI driver script: ${keriScript ?? "not found"}');

    try {
      final env = Map<String, String>.from(Platform.environment);
      env['PORT'] = '${AgentConfig.defaultDesktopPort}';
      env['HOST'] = '0.0.0.0';
      env['KERI_DRIVER_PYTHON'] = pythonBin;
      if (keriScript != null) {
        env['KERI_DRIVER_SCRIPT'] = keriScript;
      }
      if (bundledPkgDir != null) {
        final existingPythonPath = env['PYTHONPATH'] ?? '';
        env['PYTHONPATH'] = existingPythonPath.isEmpty
            ? bundledPkgDir
            : '$bundledPkgDir${Platform.isWindows ? ';' : ':'}$existingPythonPath';
        debugPrint('[BackendProcess] PYTHONPATH set to: ${env['PYTHONPATH']}');
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
      _appendOutput('[startup] Go backend started (PID: ${_backendProcess!.pid})');

      _backendProcess!.stdout.transform(const SystemEncoding().decoder).listen(
        (data) {
          debugPrint('[Backend] $data');
          for (final line in data.split('\n')) {
            if (line.trim().isNotEmpty) _appendOutput('[go] $line');
          }
        },
      );
      _backendProcess!.stderr.transform(const SystemEncoding().decoder).listen(
        (data) {
          debugPrint('[Backend:err] $data');
          for (final line in data.split('\n')) {
            if (line.trim().isNotEmpty) _appendOutput('[go:err] $line');
          }
        },
      );

      bool processExited = false;
      int? exitCode;
      _backendProcess!.exitCode.then((code) {
        debugPrint('[BackendProcess] Exited with code: $code');
        _appendOutput('[exit] Backend exited with code: $code');
        processExited = true;
        exitCode = code;
        _isRunning = false;
        _backendProcess = null;
        if (code != 0) {
          final lastLines = _backendOutput
              .where((l) => l.startsWith('[go]') || l.startsWith('[go:err]'))
              .toList();
          final tail = lastLines.length > 10
              ? lastLines.sublist(lastLines.length - 10)
              : lastLines;
          final details = tail.isNotEmpty
              ? '\n\nBackend output:\n${tail.join('\n')}'
              : '';
          _startupError = 'Backend process exited with code $code.$details';
        }
      });

      final healthy = await _waitForHealthy(() => processExited, backendDir: backendDir);
      if (!healthy) {
        if (processExited && exitCode != null && exitCode != 0) {
          // _startupError already set by exitCode.then callback with backend output
        } else {
          final lastLines = _backendOutput
              .where((l) => l.startsWith('[go]') || l.startsWith('[go:err]'))
              .toList();
          final tail = lastLines.length > 10
              ? lastLines.sublist(lastLines.length - 10)
              : lastLines;
          final details = tail.isNotEmpty
              ? '\n\nBackend output:\n${tail.join('\n')}'
              : '';
          _startupError ??=
              'Backend started but did not respond within 15 seconds.$details';
        }
        await _writeDiagnosticLog(backendDir);
        return false;
      }
      return true;
    } catch (e) {
      debugPrint('[BackendProcess] Failed to start: $e');
      _appendOutput('[startup] Exception: $e');
      _startupError = 'Failed to start backend: $e';
      _isRunning = false;
      await _writeDiagnosticLog(backendDir);
      return false;
    }
  }

  /// Read the actual port from the .port file written by the Go backend.
  /// Returns the discovered port, or the default if the file doesn't exist yet.
  int _discoverActualPort(String backendDir) {
    // The Go backend writes data/.port relative to its working directory
    final portFile = File('$backendDir${Platform.pathSeparator}data${Platform.pathSeparator}.port');
    try {
      if (portFile.existsSync()) {
        final content = portFile.readAsStringSync().trim();
        final port = int.tryParse(content);
        if (port != null && port > 0 && port < 65536) {
          return port;
        }
      }
    } catch (e) {
      debugPrint('[BackendProcess] Could not read .port file: $e');
    }
    return AgentConfig.defaultDesktopPort;
  }

  Future<bool> _waitForHealthy(bool Function() hasProcessExited, {required String backendDir}) async {
    final client = HttpClient();
    client.connectionTimeout = const Duration(seconds: 2);

    for (int i = 0; i < 30; i++) {
      if (hasProcessExited()) {
        debugPrint('[BackendProcess] Process already exited — aborting health check');
        client.close();
        return false;
      }

      // On each attempt, check for the .port file to discover the actual port
      final actualPort = _discoverActualPort(backendDir);
      if (actualPort != AgentConfig.desktopPort) {
        AgentConfig.desktopPort = actualPort;
        _appendOutput('[startup] Backend running on fallback port $actualPort');
        debugPrint('[BackendProcess] Discovered actual port: $actualPort');
      }

      try {
        final request = await client.getUrl(
          Uri.parse('http://127.0.0.1:${AgentConfig.desktopPort}/api/health'),
        );
        final response = await request.close();
        if (response.statusCode == 200) {
          debugPrint('[BackendProcess] Backend is healthy (attempt ${i + 1}) on port ${AgentConfig.desktopPort}');
          _appendOutput('[startup] Backend healthy (attempt ${i + 1}) on port ${AgentConfig.desktopPort}');
          client.close();
          return true;
        }
      } catch (_) {}
      await Future.delayed(const Duration(milliseconds: 500));
    }
    client.close();
    debugPrint('[BackendProcess] Health check timed out after 15s');
    _appendOutput('[startup] Health check timed out after 15s');
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
