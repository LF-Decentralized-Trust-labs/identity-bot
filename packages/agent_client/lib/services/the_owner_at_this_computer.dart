import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart' show kIsWeb, visibleForTesting;
import 'package:http/http.dart' as http;

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
/// SENT ONLY TO A CORE THAT HAS PROVED ITSELF. Another program can be
/// listening where the app expects its core (on a phone, any app may take the
/// port first), and a secret sent there is given away. So before the secret
/// goes anywhere, the core is asked to prove it holds it ([proveTheCoreAt]): a
/// MAC, keyed by the secret, of a fresh nonce and the port it listens on.
/// Binding the port means a program on the expected port cannot pass the
/// question through to the real core elsewhere and hand back its answer.
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
  static Uri? _proven;

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
  /// Nothing is sent with it until a core proves it holds it.
  static void use(String secret) {
    _current = secret.trim();
    _proven = null;
  }

  /// The proof a core holding [secret], listening on [port], gives for
  /// [nonce]. The same computation as the core's (server.LocalOwnerProof).
  static String proof(String secret, String nonce, int port) {
    final mac = Hmac(sha256, utf8.encode(secret))
        .convert(utf8.encode('identity-agent local owner proof\n$port\n$nonce'));
    return base64Url.encode(mac.bytes).replaceAll('=', '');
  }

  /// Asks the core at [origin] to prove it holds the secret, and from then on
  /// sends the secret there and nowhere else. Returns whether it did.
  static Future<bool> proveTheCoreAt(String origin,
      {http.Client? using}) async {
    final secret = _current;
    final at = Uri.tryParse(origin);
    if (kIsWeb || secret == null || secret.isEmpty || at == null) return false;
    final r = Random.secure();
    final nonce = base64Url
        .encode(List<int>.generate(24, (_) => r.nextInt(256)))
        .replaceAll('=', '');
    // Never the transport: until this answers, nothing may carry the secret.
    final client = using ?? http.Client();
    try {
      final resp = await client
          .get(at.replace(
              path: '/api/local-owner/proof', queryParameters: {'nonce': nonce}))
          .timeout(const Duration(seconds: 3));
      if (resp.statusCode != 200) return false;
      final got = (jsonDecode(resp.body) as Map)['proof']?.toString() ?? '';
      if (got != proof(secret, nonce, at.port)) return false;
      _proven = at;
      return true;
    } catch (_) {
      return false;
    } finally {
      if (using == null) client.close();
    }
  }

  /// Whether a request to [url] goes to the core that proved itself.
  static bool isTheProvenCore(Uri url) {
    final p = _proven;
    if (p == null) return false;
    const loopback = {'127.0.0.1', 'localhost', '::1', '[::1]'};
    return loopback.contains(url.host) &&
        loopback.contains(p.host) &&
        url.port == p.port &&
        url.scheme == p.scheme;
  }

  /// The header to send to [url]: the secret if [url] is the proven core.
  static Map<String, String> headersFor(Uri url) {
    final s = _current;
    if (kIsWeb || s == null || s.isEmpty || !isTheProvenCore(url)) return const {};
    return {header: s};
  }

  @visibleForTesting
  static void forget() {
    _current = null;
    _proven = null;
  }
}

/// The transport every request from this app goes through.
///
/// It adds the [LocalOwnerSecret] to a request for the core that proved it
/// holds it, and to nothing else, so the secret never reaches a relay, a
/// witness, another person's agent or a program impersonating the core. Every
/// client in this package is built on it, which is what makes "a request to
/// the local core carries the secret" true of a request somebody adds
/// tomorrow.
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
    request.headers.addAll(LocalOwnerSecret.headersFor(request.url));
    return _inner.send(request);
  }

  @override
  void close() => _inner.close();
}
