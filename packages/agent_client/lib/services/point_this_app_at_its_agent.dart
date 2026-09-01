import 'package:flutter/foundation.dart';

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
Future<void> pointThisAppAtItsAgent() async {
  final half = await WhichHalfThisAppIsRunning.now();
  AgentConfig.agentOrigin = half.agentOrigin;
  if (half.isAController) {
    debugPrint('[controller] this app is the front end for ${half.agentAid} '
        'at ${half.agentOrigin}');
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
