import 'dart:convert';

import 'package:http/http.dart' as http;

import 'the_path_a_signature_covers.dart';

/// Reaching a machine you own but are not sitting at.
///
/// The machine cannot tell who is calling from the connection — its owner is
/// remote by definition — so every owner route there answers "sign this". The
/// key that satisfies it is NOT the root key. A machine is adopted by a
/// pairwise identity this device minted for that machine alone, and that
/// identity is what the machine sealed and what it checks against. Signing with
/// the root produces a signature that verifies nowhere, which is a failure with
/// no visible cause.
///
/// THIS DEVICE HOLDS THE KEY BUT NEVER HANDS IT OVER. The pairwise key is
/// derived from the root seed at an index only the local core wrote down, so the
/// signing happens there — `POST /api/machines/owner/sign` — and this client
/// asks for it per request. [OwnerSigningClient] signs in Dart from a seed the
/// caller supplies, which suits the root identity and cannot reach these: the
/// index is deliberately never handed out.
///
/// IT SIGNS ONLY REQUESTS TO THE MACHINE IT IS POINTED AT, for the reason every
/// client here does. The same client resolves other people's discovery records
/// and talks to relays and witnesses, and attaching an identifier to those would
/// hand it to every stranger it looks up — the opposite of what a pairwise
/// identifier is for.
///
/// What it deliberately does NOT do is fall back. If the local core will not
/// sign, the request goes unsigned and the machine refuses it. Signing as
/// anything else — the root, another machine's identity — would be a request
/// that fails at the far end with a reason nobody can see.
class SigningAsTheIdentityThatOwnsAMachine extends http.BaseClient {
  SigningAsTheIdentityThatOwnsAMachine({
    required this.machineOrigin,
    required this.localCoreOrigin,
    required this.ownerAid,
    http.Client? inner,
  }) : _inner = inner ?? http.Client();

  /// The machine this device owns, as scheme://host:port. Requests anywhere
  /// else are passed through untouched.
  final String machineOrigin;

  /// This device's own core, which can derive the pairwise key and does the
  /// signing.
  final String localCoreOrigin;

  /// Which of this device's minted identities owns that machine.
  ///
  /// Read from the machine itself — it reports the owner it sealed — rather than
  /// remembered here. The machine is the side that decides which signature it
  /// will accept, so its answer is the one that matters, and a second copy on
  /// this device would be a second place for it to be wrong.
  ///
  /// Async and called per request rather than held: a machine can be adopted, or
  /// forgotten, while the app is running.
  final Future<String?> Function() ownerAid;

  final http.Client _inner;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    if (!_isTheMachine(request.url)) {
      return _inner.send(request);
    }
    // Only a plain Request can be signed: the body has to be read to digest it
    // and a stream can be read once. A streamed upload is passed through rather
    // than half-consumed, so it fails at the machine instead of arriving cut
    // off.
    if (request is! http.Request) {
      return _inner.send(request);
    }

    final headers = await _askThisDeviceToSign(request);
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

  /// Asks the local core to sign this request as the machine's owner.
  ///
  /// Returns null when it will not, and the request then goes unsigned. Null is
  /// deliberately not an exception: an identity not yet minted, a core still
  /// starting, or a machine this device does not own are ordinary states, and
  /// the machine's own refusal says more about what to do next than a transport
  /// error would.
  Future<Map<String, String>?> _askThisDeviceToSign(http.Request request) async {
    final aid = await ownerAid();
    if (aid == null || aid.isEmpty) return null;
    try {
      final res = await _inner.post(
        Uri.parse('$localCoreOrigin/api/machines/owner/sign'),
        headers: const {'Content-Type': 'application/json'},
        body: jsonEncode({
          'owner_aid': aid,
          'method': request.method,
          // The path the machine will actually verify — its own, with no host
          // and no relay mount prefix. A signature over the host breaks when a
          // relay renames it; a signature over the mount prefix breaks because a
          // path-mounting relay strips that prefix before the machine sees the
          // request, so the machine verifies `/api/…` and a prefixed signature
          // matches nothing. pathSignatureCovers removes the prefix, and leaves
          // a bare origin's path untouched.
          'path': pathSignatureCovers(machineOrigin, request.url),
          'body_b64': base64.encode(request.bodyBytes),
        }),
      );
      if (res.statusCode != 200) return null;

      final body = jsonDecode(res.body) as Map<String, dynamic>;
      final sig = (body['signature'] ?? '').toString();
      final stamp = (body['timestamp'] ?? '').toString();
      if (sig.isEmpty || stamp.isEmpty) return null;

      return {
        'X-IA-Owner-Sig': sig,
        // Echoed back from the core rather than formatted again here. The moment
        // is inside the signature, so a second formatting that differs by a
        // millisecond or a zone signs a string the machine never sees.
        'X-IA-Owner-Timestamp': stamp,
        'X-IA-Owner-AID': (body['owner_aid'] ?? aid).toString(),
      };
    } catch (_) {
      // Unreachable local core. Same answer as a refusal: unsigned, and let the
      // machine say no.
      return null;
    }
  }

  /// Whether a URL belongs to the machine this device owns.
  ///
  /// Compared on scheme, host and port rather than on a prefix, because a prefix
  /// test accepts `https://my-machine.example.com.attacker.test` as the machine
  /// — a real way to be handed this identity's signature.
  bool _isTheMachine(Uri url) {
    final own = Uri.tryParse(machineOrigin);
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

/// The reader most callers want: which identity this device adopted a given
/// machine as, looked up in its own record of what it owns.
///
/// Asked of THIS DEVICE rather than of the machine. The machine's own answer —
/// `/api/owners/authority` — is owner-only, so reading it would need the
/// signature this is being used to produce. The record here was written at
/// adoption by the side that minted the identity, and it is the same fact.
///
/// A machine this device does not own returns null, and the request goes
/// unsigned. That is the honest answer: there is no identity to sign as.
Future<String?> Function() theIdentityThatAdopted(
  String machineOrigin, {
  required String localCoreOrigin,
  http.Client? using,
}) {
  return () async {
    final client = using ?? http.Client();
    try {
      final res = await client.get(Uri.parse('$localCoreOrigin/api/agents'));
      if (res.statusCode != 200) return null;
      final agents =
          ((jsonDecode(res.body) as Map<String, dynamic>)['agents'] as List?) ??
              const [];
      final want = Uri.tryParse(machineOrigin);
      if (want == null) return null;
      for (final a in agents.whereType<Map<String, dynamic>>()) {
        final url = Uri.tryParse((a['url'] ?? '').toString());
        // Matched on scheme, host and port, not on the string. A machine's
        // address is recorded with whatever path and trailing slash it arrived
        // with, and comparing the text would miss the row for the machine being
        // called — leaving the request unsigned with nothing saying why.
        if (url == null) continue;
        if (url.scheme != want.scheme ||
            url.host != want.host ||
            url.port != want.port) {
          continue;
        }
        final owner = (a['owner_aid'] ?? '').toString();
        // Empty means this machine was adopted before machines were adopted
        // pairwise, so the ROOT owns it — an answer, not a gap, and one this
        // client cannot act on: it signs only as identities minted per machine.
        return owner.isEmpty ? null : owner;
      }
      return null;
    } catch (_) {
      return null;
    } finally {
      if (using == null) client.close();
    }
  };
}
