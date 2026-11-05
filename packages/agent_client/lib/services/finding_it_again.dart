import 'package:flutter/foundation.dart';

import 'finding_an_agent_that_moved.dart';
import 'point_this_app_at_its_agent.dart';
import 'which_half_this_app_is_running.dart';

/// What startup found out about where the agent this app acts for answers. Null
/// until startup has looked; the screens read it, startup writes it.
final ValueNotifier<WhereTheAgentWent?> whereTheAgentWent =
    ValueNotifier<WhereTheAgentWent?>(null);

/// Settles which half this app runs, starts on the recorded address at once,
/// and looks for a moved agent behind the app, publishing what it finds in
/// [whereTheAgentWent]. Replaces the bare [pointThisAppAtItsAgent] at launch.
///
/// [thing] is what the person calls it ("organisation", "identity").
/// [leads] supplies addresses worth trying that the app was given elsewhere.
Future<WhereTheAgentWent> settleWhereTheAgentIs({
  required String thing,
  Future<List<String>> Function()? leads,
  Future<void> Function(WhereTheAgentWent outcome)? afterwards,
}) =>
    pointThisAppAtItsAgent(
      thing: thing,
      whereItMayHaveGone: leads,
      onChecked: (outcome) async {
        await afterwards?.call(outcome);
        whereTheAgentWent.value = outcome;
      },
    );

/// What the screen should be showing.
enum WhatTheGateShows {
  /// Nothing to say: the app, untouched.
  theApp,

  /// It had moved, was proven to be the same, and the app has switched.
  aMovedNotice,

  /// It cannot be reached right now (offline, or the machine is off). The app
  /// stays usable; this is a notice, not a wall.
  anUnreachableNotice,

  /// It is truly gone from where it was: ask where it is now.
  askingWhere,

  /// A new address is being checked.
  checking,

  /// Found, proven, switched; the person confirms.
  found,
}

/// The state behind the **find it again** experience, held once for both apps.
///
/// Presentation is shared_ui's; what differs per app is only [thing], [name]
/// and what [settle] does. Interrupts the person only when the agent is truly
/// gone: an unreachable one is a notice they can ignore, and nothing here ever
/// says "moved" unless a new address was proven.
class FindingItAgain extends ChangeNotifier {
  FindingItAgain({
    required this.thing,
    String name = '',
    ValueNotifier<WhereTheAgentWent?>? outcome,
    FindingAnAgentThatMoved? finder,
    Future<Object?> Function()? settle,
  })  : _name = name,
        _outcome = outcome ?? whereTheAgentWent,
        _finder = finder,
        _settle = settle {
    _outcome.addListener(_changed);
  }

  /// What the person calls it: "organisation" or "identity".
  final String thing;

  /// Its name, when it has one the person knows it by. Empty otherwise.
  String get name => _name;
  String _name;

  /// Sets the name once it has been read; a name is not known at startup.
  void callIt(String name) {
    if (name == _name) return;
    _name = name;
    notifyListeners();
  }

  final ValueNotifier<WhereTheAgentWent?> _outcome;
  final FindingAnAgentThatMoved? _finder;
  final Future<Object?> Function()? _settle;

  bool _leftAlone = false;
  bool _noticeDismissed = false;
  bool _tryingAgain = false;
  bool _checking = false;
  bool _found = false;

  /// Why the last typed address was refused, in words. Empty otherwise.
  String message = '';

  /// Where it now answers, after a successful find, without the scheme.
  String foundAt = '';

  /// Whether a "try again" is running.
  bool get tryingAgain => _tryingAgain;

  /// Whether the agent is truly gone from where it was (as against merely
  /// unreachable).
  bool get isGone => _outcome.value?.couldNotBeFound ?? false;

  /// What the person is told in words about the outcome.
  String get notice => _outcome.value?.sayThis ?? '';

  WhatTheGateShows get shows {
    if (_found) return WhatTheGateShows.found;
    if (_checking) return WhatTheGateShows.checking;
    final out = _outcome.value;
    if (out == null) return WhatTheGateShows.theApp;
    if (out.couldNotBeFound && !_leftAlone) return WhatTheGateShows.askingWhere;
    if (out.moved && !_noticeDismissed) return WhatTheGateShows.aMovedNotice;
    if ((out.couldNotBeReached || out.couldNotBeFound) && !_noticeDismissed) {
      return WhatTheGateShows.anUnreachableNotice;
    }
    return WhatTheGateShows.theApp;
  }

  /// A readable form of an address for a person: no scheme, no path.
  static String inWords(String address) =>
      Uri.tryParse(address)?.host.isNotEmpty == true
          ? Uri.parse(address).host
          : address;

  void _changed() {
    _tryingAgain = false;
    notifyListeners();
  }

  /// Checks [address] and, only if it is proven to be the same one, switches.
  Future<void> find(String address) async {
    _checking = true;
    message = '';
    notifyListeners();
    final finder = _finder ?? FindingAnAgentThatMoved(thing: thing);
    try {
      final current = await WhichHalfThisAppIsRunning.now();
      final out = await finder.findAgain(current: current, hints: [address]);
      if (out.moved) {
        await (_settle ?? _defaultSettle)();
        foundAt = inWords(out.origin);
        _found = true;
      } else if (out.isStillThere) {
        // It answers where it was recorded after all; nothing to switch.
        await (_settle ?? _defaultSettle)();
        _outcome.value = out;
      } else {
        message = out.reasons.isEmpty
            ? (out.couldNotBeReached
                ? 'Nothing answered. Check that this computer is online and '
                    'that the machine it runs on is switched on.'
                : 'Nothing was found there.')
            : out.reasons.join('\n');
      }
    } catch (e) {
      debugPrint('[controller] looking for the $thing failed: $e');
      message = 'Something went wrong while checking that address. Nothing '
          'was changed.';
    } finally {
      _checking = false;
      if (_finder == null) finder.dispose();
      notifyListeners();
    }
  }

  Future<Object?> _defaultSettle() => pointThisAppAtItsAgent(
      thing: thing, onChecked: (outcome) => _outcome.value = outcome);

  /// Carry on without re-pointing.
  void leaveItAlone() {
    _leftAlone = true;
    notifyListeners();
  }

  /// Bring the question back after "not now".
  void askAgain() {
    _leftAlone = false;
    notifyListeners();
  }

  /// Dismiss the notice at the top.
  void dismissNotice() {
    _noticeDismissed = true;
    notifyListeners();
  }

  /// The person has read that it was found.
  void done() {
    _found = false;
    _noticeDismissed = true;
    _outcome.value = null;
    notifyListeners();
  }

  /// Looks again where it was, in the background, for an unreachable agent.
  Future<void> tryAgain() async {
    _tryingAgain = true;
    _noticeDismissed = false;
    notifyListeners();
    await (_settle ?? _defaultSettle)();
  }

  @override
  void dispose() {
    _outcome.removeListener(_changed);
    super.dispose();
  }
}
