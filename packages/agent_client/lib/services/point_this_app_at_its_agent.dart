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
  if (half.couldNotTell) {
    // Nothing is changed on a non-answer. Clearing the origin would point a
    // running front end back at its own core, and telling that core to forget
    // the record would un-arm the protection permanently — both on a failure
    // that may last one read.
    debugPrint('[controller] leaving this app as it is: which half it runs '
        'could not be read');
    return;
  }
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
      // Retried briefly, because this is called the moment the core is asked to
      // start and a core still binding its port is the ordinary case rather
      // than the exception. Swallowing that first refusal would leave the
      // protection unarmed on exactly the launches where it matters, and say
      // nothing.
      await _keepAsking(() => client.post(
            url,
            headers: const {'Content-Type': 'application/json'},
            body: jsonEncode({
              'agent_aid': agentAid,
              'agent_url': agentOrigin,
            }),
          ));
    } else {
      // Symmetrical on purpose. An installation that stopped being a front end
      // and left the record behind would have a core refusing every question
      // about the identity it now holds — locked out by its own safety net,
      // with a refusal naming an agent that is no longer anything to do with it.
      await _keepAsking(() => client.delete(url));
    }
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

/// Tries for a few seconds, because a core that has just been asked to start is
/// normally not listening yet.
///
/// Bounded rather than indefinite: if it is still refusing after this, something
/// is wrong that retrying will not fix, and the caller logs it rather than
/// holding up the app.
Future<void> _keepAsking(Future<http.Response> Function() send) async {
  Object? last;
  for (var attempt = 0; attempt < 40; attempt++) {
    try {
      final res = await send();
      // ACCEPTED IS 2xx, AND NOTHING ELSE.
      //
      // Treating anything under 500 as accepted reported the most likely real
      // failure as a success: the core refuses with 409 when it already holds
      // an identity, which is the one refusal a person can act on, and it was
      // swallowed as though it had worked. A 400 on a malformed body and a 403
      // from a caller the core does not recognise went the same way.
      if (res.statusCode >= 200 && res.statusCode < 300) return;
      // A CORE THAT HAS NEVER HEARD OF THIS IS NOT A FAILURE. An application
      // and the core beside it are pinned separately and move separately, so an
      // app that knows about this arriving before a core that does is the
      // ordinary case during a rollout — not a fault, and not something the
      // person can act on. Treating it as one would refuse to start on every
      // launch until both pins had moved.
      //
      // What it costs is the defence in depth. The app is pointed at its agent
      // either way, so its own requests go to the right place; the core beside
      // it simply cannot yet refuse the ones that reach it by mistake.
      if (res.statusCode == 404) {
        debugPrint('[controller] the core on this computer is older than this '
            'and cannot record which half the app is running — the app is '
            'pointed correctly, but that core cannot refuse a stray request');
        return;
      }
      if (res.statusCode < 500) {
        // The core read this and said no on its merits. Sending it again
        // changes nothing, and spending ten seconds doing so hides the answer.
        throw StateError('the core on this computer refused to record which '
            'half this app is running (${res.statusCode}): ${res.body}');
      }
      last = 'the core answered ${res.statusCode}';
    } on StateError {
      rethrow;
    } catch (e) {
      // A core still binding its port, which is the ordinary case at start-up.
      last = e;
    }
    await Future<void>.delayed(const Duration(milliseconds: 250));
  }
  throw StateError('the core on this computer never accepted which half this '
      'app is running: $last');
}
