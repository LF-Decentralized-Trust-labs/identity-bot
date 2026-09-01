import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:agent_client/config/agent_config.dart';

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
  /// Whether the app starting this backend serves a person or an organization.
  ///
  /// Set by the app before [start]. This glue is shared by the app for
  /// individuals and the app for organizations alike, so it must not assume
  /// either — and the backend it starts cannot work it out for itself, since
  /// the same Go core is used by both.
  ///
  /// It decides who may witness and watch for this agent: peers are of the same
  /// kind, and an agent that has not been told enrols none. Left null the
  /// backend falls back to the profile, which is empty until onboarding ends.
  static String? entityType;

  static BackendProcessService? _instance;
  Process? _backendProcess;
  bool _isRunning = false;
  String? _backendPath;
  String? _startupError;
  PortConflictInfo? _portConflict;
  final List<String> _backendOutput = [];
  static const int _maxOutputLines = 200;

  /// Where this app's Identity Agent keeps its data.
  ///
  /// Null uses the default beside the application itself, which assumes one
  /// identity per installation. An app that holds more than one — several
  /// identities a person chooses between — needs a directory per identity, and
  /// only the app knows how it divides them. Set this before [start].
  ///
  /// It is deliberately not derived from anything: a scheme that guessed would
  /// have to be guessed the same way by every consumer, and would move under
  /// them when it changed.
  static String? dataDirOverride;

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

  // Absolute, per-app writable data dir. Namespaced by the app/executable name
  // so the oss / Grape ID / Grape ID Org flavors don't collide when run together.
  String _resolveDataDir() {
    final sep = Platform.pathSeparator;
    final home = Platform.environment['HOME'] ??
        Platform.environment['USERPROFILE'] ??
        '';
    String appName;
    try {
      appName = Platform.resolvedExecutable.split(sep).last;
    } catch (_) {
      appName = 'IdentityAgent';
    }
    if (appName.isEmpty) appName = 'IdentityAgent';

    String base;
    if (Platform.isMacOS) {
      base = '$home${sep}Library${sep}Application Support${sep}$appName';
    } else if (Platform.isWindows) {
      final appData =
          Platform.environment['APPDATA'] ?? '$home${sep}AppData${sep}Roaming';
      base = '$appData$sep$appName';
    } else {
      final xdg = Platform.environment['XDG_DATA_HOME'];
      base = (xdg != null && xdg.isNotEmpty)
          ? '$xdg$sep$appName'
          : '$home${sep}.local${sep}share${sep}$appName';
    }
    final dataDir = '$base${sep}data';
    try {
      Directory(dataDir).createSync(recursive: true);
    } catch (_) {}
    return dataDir;
  }

  String? _findBundledPython(String backendDir) {
    final sep = Platform.pathSeparator;

    // Each desktop build bundles a relocatable interpreter under backend/python.
    // Windows: backend\python\python.exe ; macOS/Linux: backend/python/bin/python3
    final candidates = Platform.isWindows
        ? [
            '$backendDir${sep}python${sep}python.exe',
            '$backendDir${sep}python${sep}python3.exe',
          ]
        : [
            '$backendDir${sep}python${sep}bin${sep}python3',
            '$backendDir${sep}python${sep}bin${sep}python3.11',
          ];
    for (final path in candidates) {
      if (File(path).existsSync()) {
        debugPrint('[BackendProcess] Found bundled Python at: $path');
        return path;
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
    // GUI-launched apps inherit a minimal PATH (no /opt/homebrew, /usr/local),
    // so bare-name lookups miss an installed Python. Search PATH names first,
    // then well-known absolute locations. Prefer 3.11 to match bundled packages.
    final candidates = Platform.isWindows
        ? <String>['python', 'python3', 'py']
        : <String>[
            'python3.11', 'python3', 'python',
            '/opt/homebrew/opt/python@3.11/bin/python3',
            '/opt/homebrew/bin/python3.11',
            '/opt/homebrew/bin/python3',
            '/usr/local/opt/python@3.11/bin/python3',
            '/usr/local/bin/python3.11',
            '/usr/local/bin/python3',
            '/usr/bin/python3',
          ];

    for (final bin in candidates) {
      try {
        // Bounded, because asking is not always cheap. /usr/bin/python3 on a Mac
        // without the Xcode command line tools is a stub that opens an install
        // dialog and waits for somebody to answer it — so this call can block
        // for as long as the dialog is up, which is forever if nobody is
        // looking. Startup then never finishes and the window never appears.
        final result = await Process.run(bin, ['--version'])
            .timeout(const Duration(seconds: 3));
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
      ).timeout(const Duration(seconds: 10));
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

  /// Kept, and deliberately not called.
  ///
  /// Installing packages at startup meant reaching for pip from inside a signed
  /// application bundle, into a Python that belongs to the operating system,
  /// while somebody waited at a window that never opened. The backend has an
  /// engine of its own, so a missing package is a reason to use it rather than
  /// a reason to start installing software on somebody's computer.
  ///
  /// Left in place because a build that genuinely ships the Python driver may
  /// want it back, deliberately and somewhere it can report progress.
  // ignore: unused_element
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
    const defaultPort = AgentConfig.defaultDesktopPort;

    // Whatever else is on the port, leave it alone.
    //
    // This scanned 5050-5059 on every launch and killed any Identity Agent it
    // found, on the theory that such a process could only be a leftover of
    // this app. It cannot: two Identity Agent apps on one machine each ran
    // this loop and each terminated the other's backend, and an app holding
    // several identities has more than one of its own. A process this app did
    // not start is not this app's to end.
    //
    // Nothing is needed in its place. The backend already walks forward from
    // the requested port when it is taken, so a busy port costs a different
    // port rather than somebody else's process.
    final conflict = await checkPortConflict(defaultPort);
    if (conflict != null) {
      _appendOutput('[startup] Port $defaultPort is in use by '
          '${conflict.processName} (PID ${conflict.pid}) — this backend will '
          'take the next free port');
    }

    // Look for the Python KERI driver FIRST, because whether it is here decides
    // whether Python matters at all.
    //
    // A build that ships the driver runs it, and needs a Python that can import
    // flask and keri. A build without it uses the Go engine inside the backend
    // and needs no Python whatsoever — so demanding one refuses to start an
    // application that would have worked perfectly.
    //
    // It used to demand one unconditionally. Once the driver stopped being
    // shipped, every desktop build stopped starting: no bundled Python, so it
    // reached for a system one, found /usr/bin/python3, could not import flask
    // or keri, and went off to pip install them from inside a signed .app
    // bundle. What a person saw was an application that opened and vanished.
    final keriScript = _findKeriDriverScript(backendDir);
    _appendOutput('[startup] KERI driver script: ${keriScript ?? "not found"}');

    String? pythonBin;
    String? bundledPkgDir;
    var useKeriDriver = false;

    if (keriScript == null) {
      debugPrint('[BackendProcess] No Python KERI driver — using the built-in engine');
      _appendOutput('[startup] No Python KERI driver — using the built-in engine');
    } else {
      // The script being present is NOT enough. A build can carry the driver's
      // source and no interpreter to run it — which is exactly what shipped
      // once Python was dropped from the bundle and the .py files stayed. So
      // the driver is used only when a Python that can actually run it exists.
      pythonBin = await _findPythonBinary(backendDir);

      if (pythonBin == null) {
        debugPrint('[BackendProcess] Driver script present but no Python — '
            'falling back to the built-in engine');
        _appendOutput('[startup] No Python for the KERI driver — using the built-in engine');
      } else {
        final isBundled = _isBundledPython(pythonBin, backendDir);
        bundledPkgDir = _findBundledPythonPackages(backendDir);
        final hasBundledDeps = isBundled || bundledPkgDir != null;

        if (hasBundledDeps) {
          debugPrint('[BackendProcess] Using bundled dependencies');
          _appendOutput('[startup] Python: $pythonBin (bundled dependencies)');
          useKeriDriver = true;
        } else if (await _checkPythonDeps(pythonBin)) {
          _appendOutput('[startup] Python: $pythonBin');
          useKeriDriver = true;
        } else {
          // Deliberately NOT installing anything here. This used to reach for
          // pip from inside a signed application bundle, on a machine whose
          // Python belongs to somebody else, while a person waited at a window
          // that never opened. The engine in the backend can do this work, so
          // the honest move is to use it and say so.
          debugPrint('[BackendProcess] Python found but flask/keri unavailable — '
              'using the built-in engine');
          _appendOutput('[startup] Python present but its KERI packages are not '
              '— using the built-in engine');
        }
      }
    }

    try {
      final env = Map<String, String>.from(Platform.environment);
      env['PORT'] = '${AgentConfig.defaultDesktopPort}';
      env['HOST'] = '0.0.0.0';
      // The backend's working dir is inside the read-only .app bundle, so its
      // default relative "./data" store can't be created. Point it at an
      // absolute, per-app writable location so multiple flavors (oss / Grape ID
      // / Grape ID Org) keep separate state.
      env['AGENT_DATA_DIR'] = dataDirOverride ?? _resolveDataDir();
      debugPrint('[BackendProcess] AGENT_DATA_DIR: ${env['AGENT_DATA_DIR']}');
      if (entityType != null && entityType!.isNotEmpty) {
        env['IDENTITY_AGENT_ENTITY_TYPE'] = entityType!;
        debugPrint('[BackendProcess] entity type: $entityType');
      } else {
        debugPrint('[BackendProcess] no entity type declared — the backend will fall back '
            'to the profile, and enrols no peer witness or watcher until one is set');
      }
      if (!useKeriDriver) {
        // Tell the backend the driver is not here, so it does not expect one.
        //
        // This is not cosmetic. The backend's self-attestation hashes a list of
        // components, and the Python driver is on that list by default. Left on
        // when the file does not exist, hashing fails, the run is reported as
        // "failed" rather than "unknown", and the trust gate blocks every key
        // operation — which surfaces to a person as their device being
        // unsupported, on hardware that supports it perfectly well.
        env['ENABLE_KERI_DRIVER'] = 'false';
      } else {
        env['KERI_DRIVER_PYTHON'] = pythonBin!;
        env['KERI_DRIVER_SCRIPT'] = keriScript!;
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
      if (useKeriDriver) {
        debugPrint('[BackendProcess] Python: $pythonBin');
        debugPrint('[BackendProcess] KERI driver: $keriScript');
      } else {
        debugPrint('[BackendProcess] engine: built in');
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
  /// Exposed for the test that locks this in. The rule it protects is easy to
  /// re-break, because the wrong path looks perfectly reasonable.
  @visibleForTesting
  int debugDiscoverActualPort(String backendDir) => _discoverActualPort(backendDir);

  int _discoverActualPort(String backendDir) {
    // Looked for where the backend actually writes it, which is its DATA
    // directory — not a fixed path under the backend directory.
    //
    // Those were the same thing while every installation kept one identity in
    // one place. They stopped being the same when each identity got its own
    // directory: the data directory is then handed over from outside, the
    // backend writes .port into that, and this went on reading a path that
    // nothing had written since.
    //
    // What it cost is out of proportion to the mistake. The backend already
    // steps forward when its port is taken and says so; this is how the app
    // learns which port it settled on. Not finding the file, the app health
    // checked the default port instead, got nothing because the backend was one
    // or two ports along, and reported that its own backend had failed to
    // start — on a machine where the only thing wrong was that something else
    // held 5050.
    final candidates = <String>[
      if (dataDirOverride != null && dataDirOverride!.isNotEmpty)
        dataDirOverride!,
      '$backendDir${Platform.pathSeparator}data',
    ];
    for (final dir in candidates) {
      final portFile = File('$dir${Platform.pathSeparator}.port');
      try {
        if (portFile.existsSync()) {
          final content = portFile.readAsStringSync().trim();
          final port = int.tryParse(content);
          if (port != null && port > 0 && port < 65536) {
            return port;
          }
        }
      } catch (e) {
        debugPrint('[BackendProcess] Could not read .port in $dir: $e');
      }
    }
    return AgentConfig.defaultDesktopPort;
  }

  Future<bool> _waitForHealthy(bool Function() hasProcessExited, {required String backendDir}) async {
    final client = HttpClient();
    client.connectionTimeout = const Duration(seconds: 2);

    // HOW LONG TO WAIT, AND WHY IT IS NOT FIFTEEN SECONDS.
    //
    // This used to give up after 30 attempts at half a second. The backend it
    // is waiting for routinely takes longer than that: it starts a KERI driver
    // and waits on it, tries to raise a tunnel, and asks for an update
    // manifest — and every one of those is SLOWER when it fails than when it
    // succeeds. A machine with no route to the update host spends seconds in
    // DNS before giving up.
    //
    // So the app reported "Backend failed to start" while the backend was
    // starting perfectly and answered two seconds later. Measured on a Mac
    // where cloudflared was refused and the update host did not resolve: window
    // closed at :41, backend bound at :43, and the app then sat on an error
    // screen in front of a working agent for the rest of the session.
    //
    // Waiting longer costs nothing when the backend is healthy — the loop exits
    // on the first success, which is usually the first or second attempt. It
    // costs only in the genuinely broken case, which is the one where a person
    // is best served by a slower answer that is right.
    const attempts = 120; // a minute, at half a second each
    for (int i = 0; i < attempts; i++) {
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
    final waited = attempts ~/ 2;
    debugPrint('[BackendProcess] Health check timed out after ${waited}s');
    _appendOutput('[startup] Health check timed out after ${waited}s');
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
