import 'dart:async';

/// Whether this app has finished starting, or switching to, the core beside it.
///
/// A front end signs every request through its own core, and until that core is
/// up on its real port, and the app has been told which agent it fronts for,
/// there is nothing correct to sign: a request made in between is signed by
/// whatever holds the default port, or for the previous profile's agent, or not
/// at all. So an app closes this around starting a core or switching profile,
/// and [ControllerSigningClient] holds every request to the agent until it
/// opens again.
///
/// Open by default. An app that never closes it, and every test that does not,
/// sees no difference.
///
/// Calls nest and overlap safely: it opens when the last one that closed it
/// ends, and it reports a failure if any of them failed.
class TheCoreIsSettled {
  const TheCoreIsSettled._();

  static int _open = 0;
  static Completer<void> _settled = Completer<void>()..complete();
  static bool _worked = true;

  /// Runs [startingOrSwitching] with the gate closed, and opens it afterwards
  /// whether or not it worked — a failed start is a refusal with a reason, not
  /// a request waiting for ever.
  static Future<T> during<T>(Future<T> Function() startingOrSwitching) async {
    _begin();
    var worked = false;
    try {
      final result = await startingOrSwitching();
      worked = true;
      return result;
    } finally {
      _end(worked: worked);
    }
  }

  static void _begin() {
    if (_open == 0) {
      _settled = Completer<void>();
      _worked = true;
    }
    _open++;
  }

  static void _end({required bool worked}) {
    if (!worked) _worked = false;
    if (--_open == 0) _settled.complete();
  }

  /// Completes when nothing is starting or switching.
  ///
  /// A loop and not one wait: the waiters resume a microtask after the last
  /// [during] ends, and a new one can begin in that gap. Resuming on the old,
  /// completed signal would let a request out in the middle of that switch, so
  /// the gate is looked at again after every wake.
  static Future<void> untilSettled() async {
    while (_open > 0) {
      await _settled.future;
    }
  }

  /// False when the start or switch that just finished did not work, in which
  /// case requests to the agent are refused rather than sent.
  static bool get worked => _worked;

  /// For tests: back to open and working.
  static void reset() {
    _open = 0;
    _worked = true;
    if (!_settled.isCompleted) _settled.complete();
    _settled = Completer<void>()..complete();
  }
}
