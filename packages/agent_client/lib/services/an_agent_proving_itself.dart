import 'dart:convert';

import 'package:http/http.dart' as http;

import '../config/agent_config.dart';

/// Checking that what answers at an address holds the keys of the identity it
/// names (ADR-062, "an address also shows it holds the keys").
///
/// A key history is public, so reading one from an address shows only that the
/// address can copy a document: any host can replay it. What a host that is not
/// the agent cannot do is sign a challenge with the keys the history commits
/// to. The signing check is two signatures, one of them ML-DSA-65, and the core
/// beside this app is the one implementation of it, so this asks that core
/// (`POST /api/verify/agent-at-address`) rather than carrying a second one. The
/// core makes the challenge itself, fresh for every call, so nothing the far
/// side says can fix it in advance.
///
/// What it establishes, and no more: that whatever answered at this origin just
/// now holds the keys the identifier has in force. It is not tied to the
/// connection that follows, which is why [AnAgentAddress] insists on https
/// wherever the far side is not this computer.

/// An agent that proved it holds its identifier's keys.
class ProvedAgent {
  const ProvedAgent({required this.aid, required this.publicKey});

  /// Which identity answers there.
  final String aid;

  /// The key its history ends with.
  final String publicKey;
}

/// Why an agent could not be proved. Three kinds, because they call for
/// different words to a person.
enum NotProved {
  /// Nothing answered: a typo, a server that is down, a network that is off.
  /// Says nothing about who is there.
  noAnswer,

  /// Something answered and could not prove it holds the identity's keys, or
  /// answered for another identity. NOT the agent that was meant.
  somethingElse,

  /// This computer could not run the check at all (its own core is down or has
  /// no key engine). Not a verdict on the far side.
  couldNotTell,
}

/// An agent at an address could not be proved. [words] is for the screen;
/// [detail] is for the log and never shown.
class AnAgentCouldNotBeProved implements Exception {
  const AnAgentCouldNotBeProved(this.kind, this.words, [this.detail = '']);
  final NotProved kind;
  final String words;
  final String detail;
  @override
  String toString() => 'AnAgentCouldNotBeProved($kind): $words $detail';
}

/// Asks this computer's own core to prove who answers at [agentOrigin].
///
/// [aid], when given, is the identity this computer remembers; an address that
/// answers for another one is refused. Without it the identity is learned from
/// the answer, which is how a first connection finds out.
///
/// Throws [AnAgentCouldNotBeProved] for every way it is not proved.
Future<ProvedAgent> proveTheAgentAt(
  String agentOrigin, {
  String? aid,
  String? localCoreOrigin,
  http.Client? client,
}) async {
  final own = client == null;
  final c = client ?? http.Client();
  try {
    final http.Response res;
    try {
      res = await c
          .post(
            Uri.parse(
                '${localCoreOrigin ?? AgentConfig.coreBaseUrl}/api/verify/agent-at-address'),
            headers: const {'Content-Type': 'application/json'},
            body: jsonEncode({'address': agentOrigin, 'aid': aid ?? ''}),
          )
          // The core allows itself 15 seconds per read it makes, and makes two.
          .timeout(const Duration(seconds: 40));
    } catch (e) {
      throw AnAgentCouldNotBeProved(
          NotProved.couldNotTell,
          'This computer could not check who is at that address.',
          'the core beside this app did not answer: $e');
    }
    if (res.statusCode != 200) {
      throw AnAgentCouldNotBeProved(
          NotProved.couldNotTell,
          'This computer could not check who is at that address.',
          'the core answered ${res.statusCode}: ${res.body}');
    }
    final Object? body;
    try {
      body = jsonDecode(res.body);
    } catch (_) {
      throw const AnAgentCouldNotBeProved(NotProved.couldNotTell,
          'This computer could not check who is at that address.',
          'the core answered something that is not JSON');
    }
    if (body is! Map<String, dynamic>) {
      throw const AnAgentCouldNotBeProved(NotProved.couldNotTell,
          'This computer could not check who is at that address.',
          'the core answered something that is not an object');
    }
    final proved = body['verified'] == true;
    final provedAid = (body['aid'] ?? '').toString();
    final key = (body['public_key'] ?? '').toString();
    if (proved && provedAid.isNotEmpty && key.isNotEmpty &&
        (aid == null || aid.isEmpty || aid == provedAid)) {
      return ProvedAgent(aid: provedAid, publicKey: key);
    }
    final why = (body['why'] ?? 'no reason given').toString();
    switch ((body['kind'] ?? '').toString()) {
      case 'no-answer':
        throw AnAgentCouldNotBeProved(NotProved.noAnswer,
            'Nothing answered at that address. Check it and try again.', why);
      case 'could-not-tell':
        throw AnAgentCouldNotBeProved(NotProved.couldNotTell,
            'This computer could not check who is at that address.', why);
      default:
        throw AnAgentCouldNotBeProved(
            NotProved.somethingElse,
            'Something answered at that address, but it could not show that '
            'it is the one you meant.',
            why);
    }
  } finally {
    if (own) c.close();
  }
}
