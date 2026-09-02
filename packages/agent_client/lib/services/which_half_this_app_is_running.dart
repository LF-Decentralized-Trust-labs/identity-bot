import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../config/agent_config.dart';
import 'profile_scope.dart';

/// Whether this installation holds the identity, or is a front end for one held
/// somewhere else.
///
/// The Identity Agent is one application with two halves. Normally both run
/// here: the local core holds the identity and the screens talk to it. When the
/// identity lives on a sealed machine, that machine runs the back end and this
/// installation runs **only** the front end — controller mode — and every screen
/// has to reach the agent instead of the core on this computer.
///
/// THE DEFAULT IS THE ORDINARY CASE, and it has to be, because the alternative
/// is worse than an error. A screen that quietly kept talking to the local core
/// would show a roster, a policy or a credential belonging to nobody, and
/// nothing would report a problem. So this is stored, read once at startup, and
/// consulted by whatever builds a client — never guessed per screen.
///
/// Recorded per profile, like everything else the client keeps: one
/// installation may hold its own identity and be a front end for a different
/// one, and a single flat setting would make the second overwrite the first.
@immutable
class WhichHalfThisAppIsRunning {
  const WhichHalfThisAppIsRunning._({
    required this.agentOrigin,
    required this.agentAid,
  }) : couldNotTell = false;

  /// This installation holds the identity: the local core is the agent.
  const WhichHalfThisAppIsRunning.itHoldsTheIdentity()
      : agentOrigin = '',
        agentAid = '',
        couldNotTell = false;

  /// The settings could not be read, so this is not an answer.
  ///
  /// A THIRD STATE, because two were not enough and the missing one was
  /// dangerous. "It holds the identity" and "we do not know" look identical
  /// from the outside — both have no agent — and a caller that treats the
  /// second as the first acts on a guess. The guess un-armed a real front end:
  /// a transient read failure said "not a controller", which told the core
  /// beside it to forget the record, and it stayed forgotten after the settings
  /// came back.
  const WhichHalfThisAppIsRunning.couldNotBeRead()
      : agentOrigin = '',
        agentAid = '',
        couldNotTell = true;

  /// The origin of the agent this app is a front end for, empty when this
  /// installation holds the identity itself.
  final String agentOrigin;

  /// Which identity that agent is.
  ///
  /// Stored alongside the address because an address is not an identity: a
  /// relay allocation can be reassigned, and a machine answering at the
  /// expected place is not the same as the machine that was authorised. Knowing
  /// the identifier is what makes the next launch safe rather than trusting
  /// whatever answers.
  final String agentAid;

  /// True when the settings could not be read, so nothing below is an answer.
  ///
  /// Callers that only ask "where do requests go" can ignore it and get the
  /// local core, which is the safe read. Callers that CHANGE something on the
  /// strength of it must not: acting on a non-answer is how a working front end
  /// gets un-armed.
  final bool couldNotTell;

  /// True when this app is only the front end.
  bool get isAController => agentOrigin.isNotEmpty;

  /// Where a screen's requests should go.
  ///
  /// The single place that answers it. Callers must not fall back to
  /// [AgentConfig.coreBaseUrl] when this returns something — reaching the local
  /// core in controller mode is the failure this type exists to prevent, and it
  /// fails silently rather than loudly.
  String get baseUrl => isAController ? agentOrigin : AgentConfig.coreBaseUrl;

  static const _originKey = 'controller_agent_origin';
  static const _aidKey = 'controller_agent_aid';

  /// Records that this app is a front end for an agent elsewhere.
  ///
  /// Both parts are required. An origin without an identifier would leave the
  /// app trusting whatever answers at an address, which is the thing the
  /// identifier is kept for.
  static Future<void> pointAt({
    required String agentOrigin,
    required String agentAid,
  }) async {
    final origin = agentOrigin.trim();
    final aid = agentAid.trim();
    if (origin.isEmpty || aid.isEmpty) {
      throw ArgumentError(
          'pointing this app at an agent needs both where it is and which '
          'identity it is — an address alone would mean trusting whatever answers');
    }
    final prefs = await SharedPreferences.getInstance();
    final scope = await ProfileScope.activeId();
    await prefs.setString('$scope.$_originKey', origin);
    await prefs.setString('$scope.$_aidKey', aid);
  }

  /// Stops being a front end: this installation goes back to its own core.
  static Future<void> stopPointingElsewhere() async {
    final prefs = await SharedPreferences.getInstance();
    final scope = await ProfileScope.activeId();
    await prefs.remove('$scope.$_originKey');
    await prefs.remove('$scope.$_aidKey');
  }

  /// What this installation is, for the profile that is open.
  static Future<WhichHalfThisAppIsRunning> now() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final scope = await ProfileScope.activeId();
      final origin = prefs.getString('$scope.$_originKey') ?? '';
      final aid = prefs.getString('$scope.$_aidKey') ?? '';
      // Half a record is not a record. Rather than point at an address with no
      // identifier — the state pointAt refuses to create — treat it as absent,
      // so the app is an ordinary installation instead of a controller that
      // trusts anything answering.
      if (origin.isEmpty || aid.isEmpty) {
        return const WhichHalfThisAppIsRunning.itHoldsTheIdentity();
      }
      return WhichHalfThisAppIsRunning._(agentOrigin: origin, agentAid: aid);
    } catch (e) {
      // Unreadable settings mean this app does not know what it is. The safe
      // answer is the ordinary one: talk to the local core, which will simply
      // have no identity, rather than send signed requests somewhere unverified.
      debugPrint('[controller] could not read which half this app is: $e');
      // NOT "it holds the identity". Saying that here is a guess dressed as an
      // answer, and the guess is acted on: it tells the core beside this app to
      // forget that it is a front end, which stays forgotten after the settings
      // come back. Reading it is the safe direction; writing on it is not.
      return const WhichHalfThisAppIsRunning.couldNotBeRead();
    }
  }
}
