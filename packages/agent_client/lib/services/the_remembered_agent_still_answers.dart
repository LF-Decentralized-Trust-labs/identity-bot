import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import 'an_agent_proving_itself.dart';
import 'which_half_this_app_is_running.dart';

/// On every launch of an app that is a front end for an agent elsewhere: does
/// the same agent still answer at the remembered address?
///
/// An address is not an identity. A server can be rebuilt, a domain can lapse
/// and be bought by somebody else, and a relay allocation can be reassigned,
/// and in each case something else now answers where the organisation used to.
/// Remembering the address and the identifier is what makes the next launch
/// able to notice; this is the noticing. The same proof the first connection
/// made ([proveTheAgentAt]) is made again against the STORED identifier, and
/// the app stops, with a screen that says so, when it fails. It does not rely on
/// the far side refusing a machine it does not know, which a different agent
/// will not do for a request it cannot read.
///
/// ONLY A DIFFERENT AGENT STOPS THE APP. An agent that does not answer — the
/// server is down, this computer is offline — is [TheRememberedAgent.cannotTell]
/// and the app goes on, as it always has when the network is off. Treating
/// "unreachable" as "swapped" would lock people out of their own organisation
/// whenever the wifi dropped.
enum TheRememberedAgent {
  /// This installation holds its own identity, so there is nothing to check.
  nothingRemembered,

  /// The agent answered and proved it holds the remembered identifier's keys.
  stillThere,

  /// Something answers at the address and it is not the remembered agent.
  /// Nothing may be shown from it or sent to it.
  somethingElseAnswers,

  /// Nothing could be established either way: no answer, or this computer could
  /// not run the check.
  cannotTell,
}

Future<TheRememberedAgent> checkTheRememberedAgent({
  String? localCoreOrigin,
  http.Client? client,
}) async {
  final half = await WhichHalfThisAppIsRunning.now();
  // The settings could not be read: not an answer, so nothing is concluded.
  if (half.couldNotTell) return TheRememberedAgent.cannotTell;
  if (!half.isAController) return TheRememberedAgent.nothingRemembered;
  try {
    await proveTheAgentAt(half.agentOrigin,
        aid: half.agentAid, localCoreOrigin: localCoreOrigin, client: client);
    return TheRememberedAgent.stillThere;
  } on AnAgentCouldNotBeProved catch (e) {
    debugPrint('[controller] the agent at ${half.agentOrigin} was not proved '
        'to be ${half.agentAid}: ${e.kind} ${e.detail}');
    return e.kind == NotProved.somethingElse
        ? TheRememberedAgent.somethingElseAnswers
        : TheRememberedAgent.cannotTell;
  }
}
