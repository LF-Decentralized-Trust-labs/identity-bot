import 'dart:convert';

import 'package:http/http.dart' as http;

/// Reaching an Identity Agent that runs on a different machine.
///
/// The Identity Agent is one application. Where its halves run is a deployment
/// question: when the identity lives on a sealed machine, that machine runs the
/// back end and this app runs the front end, in **controller mode**. So every
/// request a screen makes has to leave this computer and arrive at the agent —
/// and arrive proven, because the agent has never seen this connection before
/// and "it came from localhost" is exactly what is not true any more.
///
/// THIS COMPUTER SIGNS, BUT IT DOES NOT HOLD THE KEY. The controller's key is in
/// this machine's enclave and cannot leave it, so the signing happens in the
/// local core — `POST /api/controller/sign` — and this client asks for it per
/// request. That call is the only work a controller's own back end does, and it
/// is about the controller rather than about the identity.
///
/// IT SIGNS ONLY REQUESTS TO THE AGENT IT IS POINTED AT, for the same reason
/// [OwnerSigningClient] does. The same client resolves other people's discovery
/// records and talks to relays and witnesses; attaching this machine's
/// identifier to those would hand it to every stranger it looks up.
///
/// What it deliberately does NOT do is fall back. If the local core will not
/// sign — no enclave, no key, the core not running — the request goes unsigned
/// and the agent refuses it. Reaching for the local core's own answer instead
/// would be the failure this whole mode exists to prevent: a screen showing a
/// roster, a policy or a credential belonging to nobody, with nothing reporting
/// a problem.
class ControllerSigningClient extends http.BaseClient {
  ControllerSigningClient({
    required this.agentOrigin,
    required this.localCoreOrigin,
    this.authentication,
    http.Client? inner,
  }) : _inner = inner ?? http.Client();

  /// The agent this app is a front end for, as scheme://host:port.
  /// Requests anywhere else are passed through untouched.
  final String agentOrigin;

  /// This machine's own core, which holds the enclave key and does the signing.
  final String localCoreOrigin;

  /// What the device holding the root key last said about the person, when
  /// anything did.
  ///
  /// Carried through into the signature rather than decided here, because this
  /// machine cannot decide it: a machine may not score itself, so an
  /// authentication level is only worth anything when the root-identity device
  /// has vouched for it. Null means nothing has, and the agent will refuse the
  /// actions that need one — which is the correct outcome and a legible one.
  final Future<VouchedAuthentication?> Function()? authentication;

  final http.Client _inner;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    if (!_isTheAgent(request.url)) {
      return _inner.send(request);
    }
    // Only a plain Request can be signed: the body has to be read to digest it
    // and a stream can be read once. A streamed upload is passed through rather
    // than half-consumed, so it fails at the agent instead of arriving cut off.
    if (request is! http.Request) {
      return _inner.send(request);
    }

    final headers = await _askThisMachineToSign(request);
    final signed = http.Request(request.method, request.url)
      ..headers.addAll(request.headers)
      ..bodyBytes = request.bodyBytes
      ..followRedirects = request.followRedirects
      ..maxRedirects = request.maxRedirects
      ..persistentConnection = request.persistentConnection;
    if (headers != null) {
      signed.headers.addAll(headers);
    }
    return _inner.send(signed);
  }

  /// Asks the local core to sign this request as this machine.
  ///
  /// Returns null when it will not, and the request then goes unsigned. Null is
  /// deliberately not an exception: a locked machine, a core still starting, or
  /// hardware that cannot hold a key are ordinary states, and the agent's
  /// refusal says more about what to do next than a transport error would.
  Future<Map<String, String>?> _askThisMachineToSign(http.Request request) async {
    final vouched = await authentication?.call();
    try {
      final res = await _inner.post(
        Uri.parse('$localCoreOrigin/api/controller/sign'),
        headers: const {'Content-Type': 'application/json'},
        body: jsonEncode({
          'method': request.method,
          // The path only, with no query and no host — the agent signs the same
          // thing. A signature over a full URL breaks the moment the same agent
          // is reached by a different name, which is what a relay does.
          'path': request.url.path,
          'body_b64': base64.encode(request.bodyBytes),
          if (vouched != null) 'auth_level': vouched.level,
          if (vouched != null) 'auth_at': vouched.at.toUtc().toIso8601String(),
          if (vouched != null) 'auth_score': vouched.score,
        }),
      );
      if (res.statusCode != 200) return null;

      final body = jsonDecode(res.body) as Map<String, dynamic>;
      final aid = (body['controller_aid'] ?? '').toString();
      final sig = (body['signature'] ?? '').toString();
      final stamp = (body['timestamp'] ?? '').toString();
      if (aid.isEmpty || sig.isEmpty || stamp.isEmpty) return null;

      return {
        'X-IA-Controller-AID': aid,
        'X-IA-Controller-Sig': sig,
        // Echoed back from the core rather than formatted again here. The
        // moment is inside the signature, so a second formatting that differs
        // by a millisecond or a timezone produces a signature over a string the
        // agent never sees.
        'X-IA-Controller-Timestamp': stamp,
        for (final e in {
          'X-IA-Controller-Auth-Level': (body['auth_level'] ?? '').toString(),
          'X-IA-Controller-Auth-At': (body['auth_at'] ?? '').toString(),
          'X-IA-Controller-Auth-Score': (body['auth_score'] ?? '').toString(),
        }.entries)
          if (e.value.isNotEmpty) e.key: e.value,
        if (vouched?.vouchedBy.isNotEmpty ?? false)
          'X-IA-Auth-Level-Vouched-By': vouched!.vouchedBy,
      };
    } catch (_) {
      // Unreachable local core. Same answer as a refusal: unsigned, and let the
      // agent say no.
      return null;
    }
  }

  /// Whether a URL belongs to the agent this app is a front end for.
  ///
  /// Compared on scheme, host and port rather than on a prefix, because a
  /// prefix test accepts `https://agent.example.com.attacker.test` as the
  /// agent — a real way to be handed this machine's signature.
  bool _isTheAgent(Uri url) {
    final own = Uri.tryParse(agentOrigin);
    if (own == null || own.host.isEmpty) return false;
    return url.scheme == own.scheme &&
        url.host == own.host &&
        url.port == own.port;
  }

  @override
  void close() {
    _inner.close();
    super.close();
  }
}

/// How well the person was authenticated, as established by the device holding
/// the root identity and signed by it.
///
/// [vouchedBy] is that signature, over the machine it was made for, the level,
/// the moment and the score. Without it the agent treats the level as nothing
/// measured — a machine may not score itself, because software nobody can
/// attest reports whatever its operator likes.
class VouchedAuthentication {
  const VouchedAuthentication({
    required this.level,
    required this.at,
    required this.score,
    required this.vouchedBy,
  });

  final String level;
  final DateTime at;
  final int score;
  final String vouchedBy;
}
