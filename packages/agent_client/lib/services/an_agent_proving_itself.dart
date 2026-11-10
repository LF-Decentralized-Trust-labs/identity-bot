import 'dart:convert';

import 'package:http/http.dart' as http;

import '../config/agent_config.dart';
import 'an_agent_address.dart';
import 'the_owner_at_this_computer.dart';

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
  const ProvedAgent(
      {required this.aid, required this.publicKey, this.sequence});

  /// Which identity answers there.
  final String aid;

  /// The key its history ends with.
  final String publicKey;

  /// The sequence number of the last event of the history that was proved, to
  /// be kept and handed back next time ([proveTheAgentAt]'s `knownSequence`) so
  /// a history that goes backwards is refused. Null when the core did not say.
  final int? sequence;
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

  /// The address is plain http to somewhere that is not this computer (or is
  /// not an address at all). Nothing was asked of it: the proof is not tied to
  /// the traffic that follows, so it does not make http safe.
  notSecure,
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
  int? knownSequence,
  String? knownKey,
  String? localCoreOrigin,
  http.Client? client,
}) async {
  // EVERY ORIGIN, given or stored, is tidied and held to https-except-this-
  // computer here, at the one place that proves, so no caller can skip it. The
  // proof says nothing about the traffic that follows, so plain http to another
  // host is refused whatever the host answers.
  try {
    agentOrigin = AnAgentAddress.asAnOrigin(agentOrigin);
  } on ThatIsNotAnAddress catch (e) {
    throw AnAgentCouldNotBeProved(NotProved.notSecure, e.words,
        'the address $agentOrigin was refused before anything was asked');
  }
  // The route is the owner's: it asks this core to dial an address on this
  // person's behalf, so the request carries the owner's secret like every other
  // request this app makes to the core beside it.
  final own = client == null;
  final c = ProvingThisComputer.over(client);
  try {
    final http.Response res;
    try {
      res = await c
          .post(
            Uri.parse(
                '${localCoreOrigin ?? AgentConfig.coreBaseUrl}/api/verify/agent-at-address'),
            headers: const {'Content-Type': 'application/json'},
            body: jsonEncode({
              'address': agentOrigin,
              'aid': aid ?? '',
              if (knownSequence != null) 'known_sequence': knownSequence,
              if (knownSequence != null && knownKey != null)
                'known_key': knownKey,
            }),
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
      final seq = body['sequence'];
      return ProvedAgent(
          aid: provedAid, publicKey: key, sequence: seq is int ? seq : null);
    }
    final why = (body['why'] ?? 'no reason given').toString();
    switch ((body['kind'] ?? '').toString()) {
      case 'no-answer':
        throw AnAgentCouldNotBeProved(NotProved.noAnswer,
            'Nothing answered at that address. Check it and try again.', why);
      case 'not-secure':
        throw AnAgentCouldNotBeProved(NotProved.notSecure,
            'That address is not encrypted. Use the one that starts with '
            'https://.', why);
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
    // Closes only what this function made: a client handed in is its owner's.
    if (own) c.close();
  }
}

/// [proveTheAgentAt], asked again when the failure is a blip: nothing answered,
/// or this computer could not run the check. Those say nothing about who is at
/// the address, so one passing network failure must not throw away what a
/// person has done. Anything that IS a verdict (something else answers, the
/// history went backwards, the address is not encrypted) is thrown at once, and
/// a blip that lasts [attempts] asks in a row is thrown as it is.
Future<ProvedAgent> proveTheAgentAtThroughABlip(
  String agentOrigin, {
  String? aid,
  int? knownSequence,
  String? knownKey,
  String? localCoreOrigin,
  http.Client? client,
  int attempts = 4,
  Duration pause = const Duration(seconds: 2),
}) async {
  for (var asked = 1;; asked++) {
    try {
      return await proveTheAgentAt(agentOrigin,
          aid: aid,
          knownSequence: knownSequence,
          knownKey: knownKey,
          localCoreOrigin: localCoreOrigin,
          client: client);
    } on AnAgentCouldNotBeProved catch (e) {
      final blip =
          e.kind == NotProved.noAnswer || e.kind == NotProved.couldNotTell;
      if (!blip || asked >= attempts) rethrow;
      await Future<void>.delayed(pause);
    }
  }
}
