import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import 'the_core_is_settled.dart';
import 'the_owner_at_this_computer.dart';

/// What every client that signs for a remote agent does before anything leaves
/// this computer, written once.
///
/// A request to the one origin this client is for is held while the core is
/// starting or being switched ([TheCoreIsSettled]), read once into the bytes
/// that are both signed and sent — whatever kind of request it was built as —
/// signed by the local core, and sent. If any step cannot be done the request is
/// REFUSED with [ThisMachineCouldNotSign]; none of them falls back to sending it
/// unsigned, because the far end can only answer an unsigned request with a
/// refusal that blames the person.
///
/// Requests to anywhere else pass through untouched: the same client resolves
/// other people's discovery records and talks to relays and witnesses, and
/// attaching an identifier to those would hand it to every stranger.
abstract class SignsBeforeItSends extends http.BaseClient {
  SignsBeforeItSends({
    required this.signedOrigin,
    required this.waitAtMost,
    http.Client? inner,
  })  : inner = ProvingThisComputer.over(inner),
        _ownsInner = inner == null;

  /// The one origin whose requests are signed, as scheme://host:port.
  final String signedOrigin;

  /// How long a request waits for [TheCoreIsSettled] before it is refused.
  final Duration waitAtMost;

  /// The transport underneath, for the signing call as well as the request.
  final http.Client inner;

  /// Whether this wrapper created [inner] and so may close it. A borrowed inner
  /// belongs to the caller; closing it would shut a transport still in use.
  final bool _ownsInner;

  /// The headers that prove [request], read from the local core. Throws
  /// [ThisMachineCouldNotSign] when it cannot.
  Future<Map<String, String>> headersFor(http.Request request);

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    if (!_isTheOrigin(request.url)) return inner.send(request);

    await _untilTheCoreIsSettled(request.url);

    // A streamed or multipart body is read once, here, into the bytes that are
    // both signed and sent — passing it through would be an unsigned request.
    // The headers are copied AFTER finalize(): a multipart request sets its
    // content-type, boundary included, only when it is finalized, and a copy
    // taken first sends the body without the boundary that delimits it.
    final http.Request plain;
    if (request is http.Request) {
      plain = request;
    } else {
      final bytes = await request.finalize().toBytes();
      plain = http.Request(request.method, request.url)
        ..headers.addAll(request.headers)
        ..bodyBytes = bytes
        ..followRedirects = request.followRedirects
        ..maxRedirects = request.maxRedirects
        ..persistentConnection = request.persistentConnection;
    }

    final proof = await headersFor(plain);
    final signed = http.Request(plain.method, plain.url)
      ..headers.addAll(plain.headers)
      ..bodyBytes = plain.bodyBytes
      ..followRedirects = plain.followRedirects
      ..maxRedirects = plain.maxRedirects
      ..persistentConnection = plain.persistentConnection;
    signed.headers.addAll(proof);
    return inner.send(signed);
  }

  /// Holds the request while this app is starting its core or switching
  /// profile. Refuses, rather than sends, if it never settles or the start did
  /// not work.
  Future<void> _untilTheCoreIsSettled(Uri url) async {
    try {
      await TheCoreIsSettled.untilSettled().timeout(waitAtMost);
    } on TimeoutException {
      throw ThisMachineCouldNotSign(
          'this app is still starting up, try again in a moment', url);
    }
    if (!TheCoreIsSettled.worked) {
      throw ThisMachineCouldNotSign(
          'this app could not finish starting, so it has no core to sign with',
          url);
    }
  }

  /// Posts [payload] to the local core at [path] and returns its answer, which
  /// must be a JSON object with every name in [mustHave] non-empty.
  ///
  /// Anything else — unreachable, non-200, not JSON, a field missing — is
  /// [ThisMachineCouldNotSign], said in terms a person can act on.
  Future<Map<String, dynamic>> askTheCoreToSign(
    String core,
    String path,
    Map<String, dynamic> payload,
    Uri forUrl, {
    required Map<String, String> mustHave,
  }) async {
    final http.Response res;
    try {
      res = await inner.post(
        Uri.parse('$core$path'),
        headers: const {'Content-Type': 'application/json'},
        body: jsonEncode(payload),
      );
    } catch (e) {
      throw ThisMachineCouldNotSign(
          'the core on this computer at $core could not be reached ($e)',
          forUrl);
    }
    if (res.statusCode != 200) {
      throw ThisMachineCouldNotSign(
          'the core on this computer at $core answered ${res.statusCode}',
          forUrl);
    }
    final Map<String, dynamic> body;
    try {
      body = jsonDecode(res.body) as Map<String, dynamic>;
    } catch (_) {
      throw ThisMachineCouldNotSign(
          'the core on this computer at $core answered with something that is '
          'not a signature',
          forUrl);
    }
    final missing = [
      for (final e in mustHave.entries)
        if ((body[e.key] ?? '').toString().isEmpty) e.value,
    ];
    if (missing.isNotEmpty) {
      throw ThisMachineCouldNotSign(
          'the core on this computer at $core answered without '
          '${missing.join(' or ')}',
          forUrl);
    }
    return body;
  }

  /// Compared on scheme, host and port rather than on a prefix, because a
  /// prefix test accepts `https://agent.example.com.attacker.test` as the agent
  /// — a real way to be handed this machine's signature.
  bool _isTheOrigin(Uri url) {
    final own = Uri.tryParse(signedOrigin);
    if (own == null || own.host.isEmpty) return false;
    return url.scheme == own.scheme &&
        url.host == own.host &&
        url.port == own.port;
  }

  @override
  void close() {
    if (_ownsInner) inner.close();
    super.close();
  }
}

/// This machine would not sign a request, so the request was not sent.
///
/// A [http.ClientException] so everything that already treats a failed request
/// as "could not reach it" treats this the same way, instead of crashing on a
/// type nobody expects. [message] says why, in terms a person can act on.
class ThisMachineCouldNotSign extends http.ClientException {
  ThisMachineCouldNotSign(String why, Uri url)
      : super('This computer could not sign the request, so it was not sent: '
            '$why.', url);
}
