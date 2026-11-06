import 'dart:io';

import 'package:flutter/foundation.dart' show kIsWeb;

import 'backend_process_service.dart';
import 'key_math.dart';
import 'mobile_core_service.dart';

/// The core's key arithmetic for the app this runs in (ADR-061 section 7), the
/// one way an app obtains it.
///
/// On iOS and Android it is the core linked into the app, through
/// [MobileCoreService.keyMath]. On macOS and Windows it is the core binary the
/// app bundles and starts as its backend, run as a one-shot command and checked
/// before every run ([CommandKeyMath]): its SHA-256 must be the one this app
/// was built with, and its code signature by the signer of this app.
///
/// The hash is compiled into the app, from the build's
/// `--dart-define=IDENTITY_AGENT_CORE_SHA256=<sha256 of the signed binary>`, so
/// it pins the one binary the build made: a different binary by the same
/// signer, an older core for instance, is refused. On macOS the app's code
/// signature covers it. On Windows the compiled Dart code is not itself
/// signed, so there the hash is as safe as the directory the app is installed
/// in.
///
/// Nothing is resolved until the first operation, so an app may build its
/// services with this anywhere, a web build included, and only key events
/// wait on it.
class TheCoresKeyMath implements KeyMath {
  TheCoresKeyMath(
      {bool? mobile,
      String expectedSha256 = builtWith,
      Future<String> Function(String op, String request)? mobileCall,
      String? Function()? bundledBinary,
      KeyMath Function(String binary, String sha256)? command})
      : _mobile = mobile,
        _expectedSha256 = expectedSha256,
        _mobileCall = mobileCall ?? MobileCoreService.keyMath,
        _bundledBinary = bundledBinary,
        _command = command ??
            ((binary, sha256) =>
                CommandKeyMath(binaryPath: binary, expectedSha256: sha256));

  /// The SHA-256 of the core binary this app was built with, as its build
  /// defined it; empty where it defined none.
  static const builtWith = String.fromEnvironment('IDENTITY_AGENT_CORE_SHA256');

  final bool? _mobile;
  final String _expectedSha256;
  final Future<String> Function(String op, String request) _mobileCall;
  final String? Function()? _bundledBinary;
  final KeyMath Function(String binary, String sha256) _command;
  KeyMath? _resolved;

  @override
  Future<Map<String, dynamic>> run(
          String op, Map<String, dynamic> request) async =>
      (await _resolve()).run(op, request);

  Future<KeyMath> _resolve() async {
    final done = _resolved;
    if (done != null) return done;
    if (kIsWeb && _mobile == null) {
      throw KeyMathBinaryRefused('a web app has no core of its own to run');
    }
    final KeyMath km;
    if (_mobile ?? (Platform.isIOS || Platform.isAndroid)) {
      km = BridgeKeyMath(_mobileCall);
    } else {
      final binary = (_bundledBinary ??
          BackendProcessService.instance.bundledCoreBinary)();
      if (binary == null) {
        throw KeyMathBinaryRefused('this app bundles no core binary to run');
      }
      if (!RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(_expectedSha256)) {
        throw KeyMathBinaryRefused('this app was built without the SHA-256 of '
            'its core binary (IDENTITY_AGENT_CORE_SHA256)');
      }
      km = _command(binary, _expectedSha256.toLowerCase());
    }
    return _resolved = km;
  }
}
