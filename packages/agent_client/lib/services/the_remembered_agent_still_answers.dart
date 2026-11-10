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
/// NOTHING IS SHOWN FROM AN ADDRESS THAT HAS NOT JUST PROVED ITSELF. An agent
/// that does not answer — or whose check hangs or drops — is
/// [TheRememberedAgent.cannotTell], which is not "swapped" and not "fine": the
/// gate shows and sends nothing from that address, says so, and retries. Letting
/// the app carry on over a check that did not finish would let a swapped agent
/// through by making the check fail.
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

  /// The remembered address is plain http to somewhere that is not this
  /// computer (the first flow stored such addresses). It is not asked, nothing
  /// is shown from it or sent to it, and the person connects again.
  addressNotSecure,
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
    final proved = await proveTheAgentAt(half.agentOrigin,
        aid: half.agentAid,
        knownSequence: half.agentSequence,
        knownKey: half.agentKey,
        localCoreOrigin: localCoreOrigin,
        client: client);
    // Kept, so the next launch refuses a history that goes backwards.
    if (proved.sequence != null) {
      try {
        await WhichHalfThisAppIsRunning.rememberTheProvedState(
            sequence: proved.sequence!, key: proved.publicKey);
      } catch (e) {
        debugPrint('[controller] could not keep the proved key state: $e');
      }
    }
    return TheRememberedAgent.stillThere;
  } on AnAgentCouldNotBeProved catch (e) {
    debugPrint('[controller] the agent at ${half.agentOrigin} was not proved '
        'to be ${half.agentAid}: ${e.kind} ${e.detail}');
    switch (e.kind) {
      case NotProved.somethingElse:
        return TheRememberedAgent.somethingElseAnswers;
      case NotProved.notSecure:
        return TheRememberedAgent.addressNotSecure;
      case NotProved.noAnswer:
      case NotProved.couldNotTell:
        return TheRememberedAgent.cannotTell;
    }
  }
}
