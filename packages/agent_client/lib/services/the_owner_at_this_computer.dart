import 'dart:convert';
import 'dart:math';

import 'package:flutter/foundation.dart' show kIsWeb, visibleForTesting;
import 'package:http/http.dart' as http;

import '../config/agent_config.dart';

/// The secret that makes this app the owner of the core on this computer.
///
/// Being on the same computer is not enough: every program on a desktop, and
/// every app on a phone, can reach 127.0.0.1. So the app that starts the core
/// chooses a secret, hands it to the core as it starts (the environment on a
/// desktop, the start call on a phone), and sends it with every request to
/// that core. A core this app did not start wrote its secret into its data
/// directory, and this app reads it from there
/// (BackendProcessService.adoptRunningCoresSecret).
///
/// A browser has none: a page is never the owner of the core it was served
/// from, and proves itself with a session instead.
class LocalOwnerSecret {
  const LocalOwnerSecret._();

  /// The header a request to the core on this computer carries it in.
  static const header = 'X-Local-Owner-Secret';

  /// The environment variable a desktop core is started with.
  static const environmentVariable = 'IDENTITY_AGENT_LOCAL_OWNER_SECRET';

  /// The file in the core's data directory that holds it.
  static const fileName = 'local-owner-secret';

  static String? _current;

  /// The secret of the core this app talks to on this computer, once known.
  static String? get current => _current;

  /// A fresh secret for a core about to be started.
  static String mint() {
    final r = Random.secure();
    return base64Url
        .encode(List<int>.generate(32, (_) => r.nextInt(256)))
        .replaceAll('=', '');
  }

  /// Records [secret] as the one the core on this computer was started with.
  static void use(String secret) => _current = secret.trim();

  @visibleForTesting
  static void forget() => _current = null;
}

/// The transport every request from this app goes through.
///
/// It adds the [LocalOwnerSecret] to a request for the core on this computer
/// and to nothing else, so the secret never reaches a relay, a witness or
/// another person's agent. Every client in this package is built on it, which
/// is what makes "a request to the local core carries the secret" true of a
/// request somebody adds tomorrow.
class ProvingThisComputer extends http.BaseClient {
  ProvingThisComputer([http.Client? inner]) : _inner = inner ?? http.Client();

  /// One transport for code that sends a request without building a client
  /// of its own. Kept open for the life of the app, like the client a bare
  /// `http.get` would have made each time.
  static final http.Client shared = ProvingThisComputer();

  /// The transport for a client: [inner] with the secret added, or [inner]
  /// itself when it already is one.
  static http.Client over([http.Client? inner]) =>
      inner is ProvingThisComputer ? inner : ProvingThisComputer(inner);

  final http.Client _inner;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    final secret = LocalOwnerSecret.current;
    if (!kIsWeb &&
        secret != null &&
        secret.isNotEmpty &&
        isTheCoreOnThisComputer(request.url)) {
      request.headers[LocalOwnerSecret.header] = secret;
    }
    return _inner.send(request);
  }

  /// Whether [url] addresses the core on this computer: the same port on a
  /// loopback host as [AgentConfig.coreBaseUrl].
  static bool isTheCoreOnThisComputer(Uri url) {
    final core = Uri.tryParse(AgentConfig.coreBaseUrl);
    if (core == null || core.host.isEmpty) return false;
    const loopback = {'127.0.0.1', 'localhost', '::1', '[::1]'};
    return loopback.contains(url.host) &&
        loopback.contains(core.host) &&
        url.port == core.port &&
        url.scheme == core.scheme;
  }

  @override
  void close() => _inner.close();
}
