import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import '../config/agent_config.dart';
import 'which_half_this_app_is_running.dart';

/// Deciding, once, which half of the application this installation is running.
///
/// [WhichHalfThisAppIsRunning] records the answer per profile and
/// [AgentConfig.agentOrigin] is what every caller actually reads. This is the
/// one place that carries the answer from the first to the second.
///
/// IT RUNS AT STARTUP AND WHEN THE PROFILE CHANGES, and nowhere else. Reading
/// the record per request would be correct and slower; the reason it is done
/// once is different — a value read in one place cannot disagree with itself,
/// and two screens disagreeing about where the identity lives is the failure
/// this whole area exists to prevent. It is deliberately the same shape as
/// `AgentConfig.desktopPort`, which the backend discovers at startup and
/// everything then reads.
///
/// A profile switch MUST call this again. Profiles are how one installation
/// holds more than one identity, and one of them may live on a sealed machine
/// while another is local — so the answer is a property of the open profile,
/// never of the installation.
Future<void> pointThisAppAtItsAgent({http.Client? using}) async {
  final half = await WhichHalfThisAppIsRunning.now();
  AgentConfig.agentOrigin = half.agentOrigin;
  if (half.isAController) {
    debugPrint('[controller] this app is the front end for ${half.agentAid} '
        'at ${half.agentOrigin}');
  }
  await tellThisComputerWhichHalfItIsRunning(
    agentAid: half.agentAid,
    agentOrigin: half.agentOrigin,
    using: using,
  );
}

/// Tells the core on this computer which half it is running.
///
/// The app knowing is not enough, and the difference is the whole point. A core
/// with no identity answers every question about one correctly and about
/// nobody — not initialized, no credentials, an empty roster — so a screen that
/// still calls this machine shows that as the person's own with nothing on
/// either side reporting a problem. Told, the core refuses instead, and the
/// screen fails where somebody can see it.
///
/// Best-effort, and deliberately so. This runs at startup, and a core that is
/// still coming up must not stop the app from starting. What it costs when it
/// fails is the safety net rather than the behaviour: the app is already
/// pointed at the agent by the line above, so its own requests go to the right
/// place either way.
/// An empty [agentOrigin] means this installation holds the identity itself.
Future<void> tellThisComputerWhichHalfItIsRunning({
  required String agentAid,
  required String agentOrigin,
  http.Client? using,
}) async {
  final client = using ?? http.Client();
  final url = Uri.parse('${AgentConfig.coreBaseUrl}/api/controller/front-end-for');
  try {
    if (agentOrigin.isNotEmpty) {
      await client.post(
        url,
        headers: const {'Content-Type': 'application/json'},
        body: jsonEncode({
          'agent_aid': agentAid,
          'agent_url': agentOrigin,
        }),
      );
    } else {
      // Symmetrical on purpose. An installation that stopped being a front end
      // and left the record behind would have a core refusing every question
      // about the identity it now holds — locked out by its own safety net,
      // with a refusal naming an agent that is no longer anything to do with it.
      await client.delete(url);
    }
  } catch (e) {
    debugPrint('[controller] could not tell this computer which half it is '
        'running: $e');
  } finally {
    if (using == null) client.close();
  }
}

/// Forgets that this app was a front end, for the current process.
///
/// Used when a profile is closed or switched, so the next profile does not
/// inherit the previous one's agent. Separate from
/// [WhichHalfThisAppIsRunning.stopPointingElsewhere], which forgets it
/// permanently — this only clears what this process is currently using, and
/// calling the wrong one would silently unpair a working controller.
void stopPointingThisProcessAnywhere() {
  AgentConfig.agentOrigin = '';
}
