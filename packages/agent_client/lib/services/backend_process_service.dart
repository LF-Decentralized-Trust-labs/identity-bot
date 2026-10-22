import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:agent_client/config/agent_config.dart';
import 'the_owner_at_this_computer.dart';

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

  /// Settings a product gives its backend through the environment, such as
  /// which relays it is reached through (`RELAY_BASE_URL`,
  /// `PUBLIC_RELAY_BASE_URL`). Set this before [start].
  ///
  /// Each applies only when the environment does not already name it, so
  /// whoever runs the app can always point it somewhere else. The core bundles
  /// no operator of its own; this is where an app that does says so.
  static Map<String, String> environmentDefaults = const {};

  BackendProcessService._();

  /// The environment the backend starts with: [base] with each of
  /// [environmentDefaults] that [base] does not already give a value.
  @visibleForTesting
  static Map<String, String> withEnvironmentDefaults(Map<String, String> base) {
    final env = Map<String, String>.from(base);
    environmentDefaults.forEach((name, value) {
      if ((env[name] ?? '').trim().isEmpty) env[name] = value;
    });
    return env;
  }

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

    // A core already running on this profile's data is used, never joined by
    // a second one: two cores on one data directory corrupt it.
    final already = await useACoreAlreadyRunningHere();
    if (already == true) return true;
    if (already == false) {
      _appendOutput('[startup] $_startupError');
      return false;
    }

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

    try {
      final env = withEnvironmentDefaults(Platform.environment);
      env['PORT'] = '${AgentConfig.defaultDesktopPort}';
      env['HOST'] = '0.0.0.0';
      // The backend's working dir is inside the read-only .app bundle, so its
      // default relative "./data" store can't be created. Point it at an
      // absolute, per-app writable location so multiple flavors (oss / Grape ID
      // / Grape ID Org) keep separate state.
      env['AGENT_DATA_DIR'] = _backendDataDir();
      debugPrint('[BackendProcess] AGENT_DATA_DIR: ${env['AGENT_DATA_DIR']}');
      ownTheCoreAboutToStart(env);
      if (entityType != null && entityType!.isNotEmpty) {
        env['IDENTITY_AGENT_ENTITY_TYPE'] = entityType!;
        debugPrint('[BackendProcess] entity type: $entityType');
      } else {
        debugPrint('[BackendProcess] no entity type declared — the backend will fall back '
            'to the profile, and enrols no peer witness or watcher until one is set');
      }

      debugPrint('[BackendProcess] Starting: $_backendPath');
      debugPrint('[BackendProcess] Working dir: $backendDir');
      debugPrint('[BackendProcess] engine: built in (keri-go)');

      _forgetPort();
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
      // Answering is not enough: the core on that port must prove it holds the
      // secret this app gave it before the app sends that secret anywhere.
      if (healthy && !await LocalOwnerSecret.proveTheCoreAt(AgentConfig.coreBaseUrl)) {
        _startupError = 'The Identity Agent answering on port ${AgentConfig.desktopPort} '
            'did not prove it is the one this app started. Another program may be '
            'holding the port.';
        _appendOutput('[startup] $_startupError');
        await stop();
        await _writeDiagnosticLog(backendDir);
        return false;
      }
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

  /// What makes this app, and no other program on this computer, the owner of
  /// the core it is about to start with [env]. Chosen here so the app holds it
  /// before the core answers anything; every request to the core carries it.
  @visibleForTesting
  static void ownTheCoreAboutToStart(Map<String, String> env) {
    final secret = LocalOwnerSecret.mint();
    env[LocalOwnerSecret.environmentVariable] = secret;
    LocalOwnerSecret.use(secret);
  }

  /// Whether a core is already running on this profile's data directory, and
  /// if so whether this app can act as its owner.
  ///
  /// Returns null when none is running, true when one is and it proved it holds
  /// the secret it wrote (this app then uses it), and false when one is running
  /// that this app cannot act for: a core started before it wrote a secret, or
  /// one whose file is stale. Starting a second core on the same data then
  /// would corrupt it, so the person is told to quit the running one instead.
  Future<bool?> useACoreAlreadyRunningHere() async {
    final port = _discoverActualPort();
    if (port == null || !await _answersHealth(port)) return null;
    final previous = AgentConfig.desktopPort;
    AgentConfig.desktopPort = port;
    if (adoptRunningCoresSecret() &&
        await LocalOwnerSecret.proveTheCoreAt(AgentConfig.coreBaseUrl)) {
      _appendOutput('[startup] Using the Identity Agent already running on port $port');
      return true;
    }
    AgentConfig.desktopPort = previous;
    _startupError = 'An Identity Agent is already running on this profile\'s data '
        '(port $port), and this app cannot act as its owner. Quit it, or restart '
        'this computer, and open the app again.';
    return false;
  }

  Future<bool> _answersHealth(int port) async {
    final client = HttpClient()..connectionTimeout = const Duration(milliseconds: 600);
    try {
      final req = await client
          .getUrl(Uri.parse('http://127.0.0.1:$port/api/health'))
          .timeout(const Duration(milliseconds: 800));
      final resp = await req.close().timeout(const Duration(milliseconds: 800));
      await resp.drain<void>();
      return resp.statusCode == 200;
    } catch (_) {
      return false;
    } finally {
      client.close(force: true);
    }
  }

  /// Takes up the secret of a core this app did not start, from the file the
  /// core wrote into its data directory, so this app is that core's owner.
  /// For an app that attaches to a core already running rather than starting
  /// one. Returns whether a secret was found.
  bool adoptRunningCoresSecret() {
    try {
      final f = File('${_backendDataDir()}${Platform.pathSeparator}${LocalOwnerSecret.fileName}');
      if (!f.existsSync()) return false;
      final secret = f.readAsStringSync().trim();
      if (secret.isEmpty) return false;
      LocalOwnerSecret.use(secret);
      return true;
    } catch (_) {
      return false;
    }
  }

  /// Read the actual port from the .port file written by the Go backend.
  /// Returns the discovered port, or null if the backend has not written one yet.
  /// Exposed for the test that locks this in. The rule it protects is easy to
  /// re-break, because the wrong path looks perfectly reasonable.
  @visibleForTesting
  int? debugDiscoverActualPort() => _discoverActualPort();

  /// Remove a .port left from an earlier run, so the only one there is the one
  /// the backend about to start writes.
  @visibleForTesting
  void debugForgetPort() => _forgetPort();

  /// The data directory the backend is told to use, and the .port inside it.
  @visibleForTesting
  String debugBackendDataDir() => _backendDataDir();
  @visibleForTesting
  String debugPortFilePath() => _portFilePath();

  // One answer to "where does this backend keep its data", used both to tell
  // the backend and to find the port it writes there. Two answers is how the
  // app came to look in a folder the backend never wrote to.
  String _backendDataDir() {
    final override = dataDirOverride;
    return (override != null && override.isNotEmpty) ? override : _resolveDataDir();
  }

  String _portFilePath() => '${_backendDataDir()}${Platform.pathSeparator}.port';

  void _forgetPort() {
    try {
      final f = File(_portFilePath());
      if (f.existsSync()) f.deleteSync();
    } catch (e) {
      debugPrint('[BackendProcess] Could not remove an old .port: $e');
    }
  }

  int? _discoverActualPort() {
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
    final portFile = File(_portFilePath());
    try {
      if (portFile.existsSync()) {
        final port = int.tryParse(portFile.readAsStringSync().trim());
        if (port != null && port > 0 && port < 65536) {
          return port;
        }
      }
    } catch (e) {
      debugPrint('[BackendProcess] Could not read ${portFile.path}: $e');
    }
    // Not the default port as a guess. Until this backend says where it is, a
    // different program can be answering on the default — another Identity
    // Agent app on the same machine, say — and a health check there reports
    // somebody else's backend as this one. The app then talks to the wrong
    // identity entirely.
    return null;
  }

  Future<bool> _waitForHealthy(bool Function() hasProcessExited, {required String backendDir}) async {
    final client = HttpClient();
    client.connectionTimeout = const Duration(seconds: 2);

    // HOW LONG TO WAIT, AND WHY IT IS NOT FIFTEEN SECONDS.
    //
    // This used to give up after 30 attempts at half a second. The backend it
    // is waiting for routinely takes longer than that: it tries to raise a
    // tunnel and asks for an update manifest — and every one of those is SLOWER
    // when it fails than when it succeeds. A machine with no route to the update
    // host spends seconds in DNS before giving up.
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

      // On each attempt, check for the .port file to discover the actual port.
      // Nothing is probed until this backend has written one.
      final actualPort = _discoverActualPort();
      if (actualPort == null) {
        await Future.delayed(const Duration(milliseconds: 500));
        continue;
      }
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
