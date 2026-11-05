import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import 'asking_to_act_for_an_identity.dart';
import 'which_half_this_app_is_running.dart';

/// Finding an Identity Agent again after it changed address.
///
/// A front end records TWO things about the agent it acts for: which identity it
/// is, and where it answers. The first never changes. The second does — a
/// development tunnel is replaced by a stable relay name, a machine is moved, a
/// relay allocation is reassigned — and until this existed the app kept the old
/// address for ever, sent it to its core at every launch, and failed to open the
/// organisation with an error that named no cause.
///
/// WHAT MAKES A NEW ADDRESS BELIEVABLE is the whole of this file. The old
/// address cannot be asked, because it is the thing that stopped answering, and
/// whoever answers there now (or at a name somebody typed) is a stranger until
/// shown otherwise. So the app switches only when ALL of these hold, each
/// checked by this computer rather than reported by the far side:
///
///  1. An Identity Agent answers there (the one public route that describes the
///     software, not merely a 200).
///  2. The key history published there verifies and derives EXACTLY the
///     identifier this app already holds. A log that checks out cannot name
///     another identifier than its own, so this ties the address to the
///     identity without trusting the address. Checked by this computer's own
///     core.
///  3. The agent there recognises THIS computer: a request signed by this
///     machine's hardware key is accepted and answered with the same
///     identifier. Only the agent holding this machine's grant can say yes, and
///     the key history in (2) is public, so (2) alone could be copied by
///     anything; (3) cannot.
///
/// WHAT THIS DOES NOT PROVE, said plainly: the agent's answer in (3) is not
/// itself signed by the identity's key (the root key never leaves the
/// controller device), so a copy of the public log that also lies about
/// recognising this machine would pass. It would then receive only requests that
/// name the real agent and are refused by it; the signed endpoint record that
/// closes this is recorded in strategy/1-Strategy/tasks.md.
///
/// Nothing is changed unless a candidate is proven. A failed search leaves the
/// record exactly as it was.
class FindingAnAgentThatMoved {
  FindingAnAgentThatMoved({AskingToActForAnIdentity? asking, http.Client? client})
      : _asking = asking ?? AskingToActForAnIdentity(client: client),
        _ownsAsking = asking == null;

  final AskingToActForAnIdentity _asking;
  final bool _ownsAsking;

  /// Whether an Identity Agent answers at [origin] right now.
  Future<bool> answersAt(String origin) async {
    try {
      await _asking.confirmAnAgentIsAt(origin).timeout(
            const Duration(seconds: 8),
          );
      return true;
    } catch (_) {
      return false;
    }
  }

  /// Throws, with a sentence a person can read, unless [candidate] is proven to
  /// be the agent of [agentAid]. See the class note for what is checked.
  Future<void> proveItIsStillThem({
    required String agentAid,
    required String candidate,
  }) async {
    final at = _tidy(candidate);
    if (at == null) {
      throw StateError('"$candidate" is not an address this app will switch '
          'to: it must start with https:// (http:// only for this computer).');
    }
    try {
      await _asking.confirmAnAgentIsAt(at);
    } catch (e) {
      throw StateError(_plain(e));
    }
    try {
      await _asking.confirmThisIsReally(agentAid, at);
    } catch (e) {
      throw StateError(
          'something answers at $at, but it did not prove it is this '
          'organisation: ${_plain(e)}');
    }
    final WhatThisMachineWasTold? told;
    try {
      told = await _asking.whatTheAgentSays(at);
    } catch (e) {
      throw StateError('the organisation\'s key history is published at $at, '
          'but it did not answer this computer: ${_plain(e)}');
    }
    if (told == null) {
      throw StateError('the organisation\'s key history is published at $at, '
          'but the agent there does not recognise this computer, so it cannot '
          'be switched to safely');
    }
    if (told.agentAid != agentAid) {
      throw StateError('the agent at $at says it is ${told.agentAid}, not '
          '$agentAid');
    }
  }

  /// If the recorded agent no longer answers, looks at each of [hints] in order
  /// and re-points this app at the first that is proven to be the same
  /// identity. [hints] are leads, not facts: nothing in them is believed.
  Future<WhereTheAgentWent> findAgain({
    required WhichHalfThisAppIsRunning current,
    List<String> hints = const [],
  }) async {
    if (!current.isAController) return const WhereTheAgentWent.notAFrontEnd();
    if (await answersAt(current.agentOrigin)) {
      return WhereTheAgentWent.stillThere(current.agentOrigin);
    }
    final tried = <String>{current.agentOrigin};
    final reasons = <String>[];
    for (final hint in hints) {
      final at = _tidy(hint) ?? hint.trim();
      if (at.isEmpty || !tried.add(at)) continue;
      try {
        await proveItIsStillThem(agentAid: current.agentAid, candidate: at);
      } catch (e) {
        reasons.add(_plain(e));
        continue;
      }
      await WhichHalfThisAppIsRunning.pointAt(
          agentOrigin: at, agentAid: current.agentAid);
      debugPrint('[controller] ${current.agentAid} moved from '
          '${current.agentOrigin} to $at, and was proven to be the same');
      return WhereTheAgentWent.movedTo(at, from: current.agentOrigin);
    }
    return WhereTheAgentWent.notFound(current.agentOrigin, reasons);
  }

  void dispose() {
    if (_ownsAsking) _asking.dispose();
  }

  /// https, or http only to this computer; no path, query or credentials.
  static String? _tidy(String raw) {
    final u = Uri.tryParse(raw.trim());
    if (u == null || !u.hasAuthority || u.host.isEmpty) return null;
    if (u.userInfo.isNotEmpty) return null;
    final loopback =
        u.host == 'localhost' || u.host == '127.0.0.1' || u.host == '::1';
    if (u.scheme != 'https' && !(u.scheme == 'http' && loopback)) return null;
    return Uri(
            scheme: u.scheme,
            host: u.host,
            port: u.hasPort ? u.port : null)
        .toString();
  }

  static String _plain(Object e) => e
      .toString()
      .replaceFirst(RegExp(r'^(Bad state|Exception): '), '');
}

/// What looking for a moved agent came to.
@immutable
class WhereTheAgentWent {
  const WhereTheAgentWent._(this.kind, this.origin, this.from, this.reasons);
  const WhereTheAgentWent.notAFrontEnd()
      : this._(_Kind.notAFrontEnd, '', '', const []);
  const WhereTheAgentWent.stillThere(String origin)
      : this._(_Kind.stillThere, origin, '', const []);
  const WhereTheAgentWent.movedTo(String origin, {required String from})
      : this._(_Kind.movedTo, origin, from, const []);
  const WhereTheAgentWent.notFound(String old, List<String> reasons)
      : this._(_Kind.notFound, old, '', reasons);

  final _Kind kind;

  /// Where the agent answers now (moved / still there), or where it used to
  /// (not found).
  final String origin;
  final String from;

  /// Why each candidate was refused, in words for a person.
  final List<String> reasons;

  bool get moved => kind == _Kind.movedTo;
  bool get couldNotBeFound => kind == _Kind.notFound;

  /// One plain sentence for the person, or empty when there is nothing to say.
  String get sayThis {
    switch (kind) {
      case _Kind.movedTo:
        return 'This organisation has moved. It was at $from and is now at '
            '$origin. This app checked that it is the same organisation and '
            'switched to the new address.';
      case _Kind.notFound:
        return 'This organisation does not answer at $origin any more. If it '
            'has moved, use "This organisation has moved — find it again" '
            'and enter its new address; this app will check it is the same '
            'organisation before switching.';
      case _Kind.stillThere:
      case _Kind.notAFrontEnd:
        return '';
    }
  }
}

enum _Kind { notAFrontEnd, stillThere, movedTo, notFound }
