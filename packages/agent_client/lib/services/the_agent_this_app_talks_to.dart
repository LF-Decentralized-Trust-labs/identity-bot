import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:http/http.dart' as http;

import '../config/agent_config.dart';
import 'browser_session_client.dart';
import 'controller_signing_client.dart';
import 'signing_as_the_identity_that_owns_a_machine.dart';

/// Where a request about the identity goes, and what proves who is sending it.
///
/// One question, not two, and answering it in one place is the point. A service
/// that got the address right and the client wrong sends an unsigned request to
/// an agent that correctly refuses it; one that got the client right and the
/// address wrong sends a signed request to the core on this computer, which
/// answers about nobody and reports no problem. Both were possible while every
/// service picked its own.
///
/// THE ADDRESS IS NOT ALWAYS THIS COMPUTER. The Identity Agent is one
/// application with two halves, and when the identity lives on a sealed machine
/// that machine runs the back end while this installation runs only the front
/// end. Then every request about the identity has to leave here — and arrive
/// proven, because the agent has never seen this connection and "it came from
/// localhost" is exactly what stopped being true.
///
/// WHAT DOES NOT BELONG HERE is anything about THIS COMPUTER rather than about
/// the identity: installing an update, handing a seed to the core beside you.
/// Those keep [AgentConfig.coreBaseUrl] and say why, because sending them to
/// the agent would be the same failure pointing the other way.
class TheAgentThisAppTalksTo {
  const TheAgentThisAppTalksTo._();

  /// Where a request about the identity should go.
  ///
  /// The local core in the ordinary case, and the agent this app is a front end
  /// for when it is one. Set at startup from what was recorded for the open
  /// profile — never guessed per screen, because a screen that guesses wrong
  /// gets a plausible answer about nobody.
  static String get origin => AgentConfig.agentBaseUrl;

  /// A client that proves who is sending, for requests to [origin].
  ///
  /// Requests anywhere else are passed through untouched by every one of these,
  /// which is what makes it safe to use as a service's default: the same client
  /// resolves other people's discovery records and talks to relays and
  /// witnesses, and attaching an identifier to those would hand it to every
  /// stranger this app looks up.
  ///
  /// It never falls back to the local core's own answer. Where nothing can
  /// sign, the request goes unsigned and the agent refuses it — a refusal says
  /// what to do next, and a screen full of somebody else's data does not.
  /// Just the client, for the services that do not carry a session.
  ///
  /// Takes the caller's own nullable address so the client is built for the
  /// SAME place the service will send to. A service that defaulted the two
  /// separately could sign for one agent and call another, which is a signature
  /// handed to whoever is at the second.
  static http.Client clientFor([String? origin, http.Client? inner]) =>
      theAgent(origin: origin, inner: inner).client;

  /// [inner] replaces the transport underneath, never the proving. A caller can
  /// stand in for the network — a test, a client with its own timeouts — and
  /// still cannot send unsigned: which wrapper goes on top is decided here and
  /// nowhere else, which is the whole reason this function exists.
  static HowThisAppReaches theAgent({String? origin, http.Client? inner}) {
    final to = origin ?? TheAgentThisAppTalksTo.origin;

    // This app is the front end for an agent elsewhere. It signs as ITSELF —
    // the enclave key on this machine — and the agent decides what a machine
    // acting for somebody may do.
    if (AgentConfig.isAController && to == AgentConfig.agentBaseUrl) {
      return HowThisAppReaches._(
        ControllerSigningClient(
          agentOrigin: to,
          // Always this machine, never the agent: the key that signs lives here
          // and the agent cannot reach it.
          localCoreOrigin: AgentConfig.coreBaseUrl,
          inner: inner,
        ),
        null,
      );
    }

    // A machine this device owns but is not sitting at. Signed as the pairwise
    // identity that adopted it, which is the only key that machine will accept
    // — not the root, whose signature verifies here and nowhere else.
    if (!kIsWeb && to != AgentConfig.coreBaseUrl) {
      return HowThisAppReaches._(
        SigningAsTheIdentityThatOwnsAMachine(
          machineOrigin: to,
          localCoreOrigin: AgentConfig.coreBaseUrl,
          ownerAid: theIdentityThatAdopted(to,
              localCoreOrigin: AgentConfig.coreBaseUrl, using: inner),
          inner: inner,
        ),
        null,
      );
    }

    // The ordinary case: the core on this computer, which recognises a request
    // that originated on the machine it runs on. A browser holds no key, so
    // where this build is a page it carries a session instead.
    final session = BrowserSessionClient(agentOrigin: to, inner: inner);
    return HowThisAppReaches._(session, session);
  }
}

/// The client to send with, and the session it carries when it carries one.
///
/// Two fields rather than one because adopting a token has to change the client
/// that actually sends requests, so the caller needs the same object rather than
/// a second one built the same way.
class HowThisAppReaches {
  const HowThisAppReaches._(this.client, this.session);

  final http.Client client;

  /// Non-null only where this app proves itself with a session rather than a
  /// key. A key beats a session: wiring both would leave two answers to "who is
  /// this" and the agent choosing between them.
  final BrowserSessionClient? session;
}
