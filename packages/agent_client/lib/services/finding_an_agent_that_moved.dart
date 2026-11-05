import 'dart:async';

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
/// name the real agent and are refused by it. What closes this is a signed
/// record, made by the agent's own key, naming the exact address; until that is
/// checked here, an address is only as believable as the three checks above.
///
/// Nothing is changed unless a candidate is proven. A failed search leaves the
/// record exactly as it was.
class FindingAnAgentThatMoved {
  FindingAnAgentThatMoved({
    AskingToActForAnIdentity? asking,
    http.Client? client,
    this.thing = 'organisation',
  })  : _asking = asking ?? AskingToActForAnIdentity(client: client),
        _ownsAsking = asking == null;

  final AskingToActForAnIdentity _asking;
  final bool _ownsAsking;

  /// What the person calls what is being looked for: "organisation" or
  /// "identity". Every sentence this produces is for that person.
  final String thing;

  /// Whether an Identity Agent answers at [origin] right now.
  Future<bool> answersAt(String origin) async =>
      await _lookAt(origin) == TheAnswerFromThere.anAgent;

  /// What is at [origin], told apart in the way a person needs: an agent, a
  /// place that cannot be reached at all (offline, machine off), or a place that
  /// answers with something that is not the agent. Only the last is evidence
  /// that the agent is not there any more.
  Future<TheAnswerFromThere> _lookAt(String origin) async {
    try {
      await _asking.confirmAnAgentIsAt(origin).timeout(
            const Duration(seconds: 8),
          );
      return TheAnswerFromThere.anAgent;
    } on NothingAnsweredThere {
      return TheAnswerFromThere.nothing;
    } on TimeoutException {
      return TheAnswerFromThere.nothing;
    } catch (_) {
      return TheAnswerFromThere.somethingElse;
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
      throw StateError('That is not an address this app will switch to. Use a '
          'web address, such as box.example.com.');
    }
    switch (await _lookAt(at)) {
      case TheAnswerFromThere.anAgent:
        break;
      case TheAnswerFromThere.nothing:
        throw _NothingAnswered('Nothing answered at that address. Check it is '
            'spelled right and that this computer is online.');
      case TheAnswerFromThere.somethingElse:
        throw StateError('Something answers at that address, but it is not an '
            'Identity Agent.');
    }
    try {
      await _asking.confirmThisIsReally(agentAid, at);
    } catch (e) {
      debugPrint('[controller] $at did not prove it is $agentAid: $e');
      throw StateError('Something answers at that address, but it could not '
          'show that it is this $thing.');
    }
    final WhatThisMachineWasTold? told;
    try {
      told = await _asking.whatTheAgentSays(at);
    } catch (e) {
      debugPrint('[controller] $at did not answer this computer: $e');
      throw StateError('The $thing seems to be at that address, but it did not '
          'answer this computer.');
    }
    if (told == null) {
      throw StateError('The $thing there does not recognise this computer, so '
          'this app cannot switch to it safely.');
    }
    if (told.agentAid != agentAid) {
      throw StateError('What answers at that address is a different $thing.');
    }
  }

  /// If the recorded agent no longer answers, looks at each of [hints] in order
  /// and re-points this app at the first that is proven to be the same
  /// identity. [hints] are leads, not facts: nothing in them is believed.
  Future<WhereTheAgentWent> findAgain({
    required WhichHalfThisAppIsRunning current,
    List<String> hints = const [],
  }) async {
    if (!current.isAController)
      return const WhereTheAgentWent.notAFrontEnd(thing: '');
    final there = await _lookAt(current.agentOrigin);
    if (there == TheAnswerFromThere.anAgent) {
      return WhereTheAgentWent.stillThere(current.agentOrigin);
    }
    final tried = <String>{current.agentOrigin};
    final reasons = <String>[];
    var aLeadAnsweredWithSomethingElse = false;
    for (final hint in hints) {
      final at = _tidy(hint) ?? hint.trim();
      if (at.isEmpty || !tried.add(at)) continue;
      try {
        await proveItIsStillThem(agentAid: current.agentAid, candidate: at);
      } catch (e) {
        reasons.add(_plain(e));
        if (e is! _NothingAnswered) aLeadAnsweredWithSomethingElse = true;
        continue;
      }
      await WhichHalfThisAppIsRunning.pointAt(
          agentOrigin: at, agentAid: current.agentAid);
      debugPrint('[controller] ${current.agentAid} moved from '
          '${current.agentOrigin} to $at, and was proven to be the same');
      return WhereTheAgentWent.movedTo(at,
          from: current.agentOrigin, thing: thing);
    }
    // Nothing reached at all is NOT evidence of a move: this computer may be
    // offline, or the machine the agent runs on switched off. Only an address
    // that answers with something other than the agent says it is gone.
    if (there == TheAnswerFromThere.nothing &&
        !aLeadAnsweredWithSomethingElse) {
      return WhereTheAgentWent.unreachable(current.agentOrigin, thing: thing);
    }
    return WhereTheAgentWent.notFound(current.agentOrigin, reasons,
        thing: thing);
  }

  void dispose() {
    if (_ownsAsking) _asking.dispose();
  }

  /// https (assumed when no scheme is typed), or http only to this computer; no path, query or credentials.
  static String? _tidy(String raw) {
    var text = raw.trim();
    // A person types where it is, not how to speak to it.
    if (text.isNotEmpty && !text.contains('://')) text = 'https://$text';
    final u = Uri.tryParse(text);
    if (u == null || !u.hasAuthority || u.host.isEmpty) return null;
    if (u.userInfo.isNotEmpty) return null;
    final loopback =
        u.host == 'localhost' || u.host == '127.0.0.1' || u.host == '::1';
    if (u.scheme != 'https' && !(u.scheme == 'http' && loopback)) return null;
    return Uri(scheme: u.scheme, host: u.host, port: u.hasPort ? u.port : null)
        .toString();
  }

  static String _plain(Object e) =>
      e.toString().replaceFirst(RegExp(r'^(Bad state|Exception): '), '');
}

/// Nothing could be reached at an address a person typed or was given.
class _NothingAnswered extends StateError {
  _NothingAnswered(super.message);
}

/// What is at an address, as far as a person needs to tell.
enum TheAnswerFromThere { anAgent, nothing, somethingElse }

/// What looking for a moved agent came to.
@immutable
class WhereTheAgentWent {
  const WhereTheAgentWent._(
      this._kindOf, this.origin, this.from, this.reasons, this.thing);
  const WhereTheAgentWent.notAFrontEnd({String thing = ''})
      : this._(_Kind.notAFrontEnd, '', '', const [], thing);

  /// The look has not finished: the app has started on the recorded address
  /// and is checking, in the background, that it still answers.
  const WhereTheAgentWent.notCheckedYet()
      : this._(_Kind.notCheckedYet, '', '', const [], '');
  const WhereTheAgentWent.stillThere(String origin)
      : this._(_Kind.stillThere, origin, '', const [], '');
  const WhereTheAgentWent.movedTo(String origin,
      {required String from, String thing = 'organisation'})
      : this._(_Kind.movedTo, origin, from, const [], thing);
  const WhereTheAgentWent.notFound(String old, List<String> reasons,
      {String thing = 'organisation'})
      : this._(_Kind.notFound, old, '', reasons, thing);

  /// Nothing could be reached at the recorded address and no lead was proven:
  /// this computer may be offline or the agent's machine switched off. It is
  /// NOT said to have moved.
  const WhereTheAgentWent.unreachable(String origin,
      {String thing = 'organisation'})
      : this._(_Kind.unreachable, origin, '', const [], thing);

  final _Kind _kindOf;

  /// Where the agent answers now (moved / still there), or where it used to
  /// (not found / unreachable).
  final String origin;
  final String from;

  /// Why each candidate was refused, in words for a person.
  final List<String> reasons;

  /// What the person calls it: "organisation" or "identity".
  final String thing;

  bool get isStillThere => _kindOf == _Kind.stillThere;
  bool get moved => _kindOf == _Kind.movedTo;
  bool get couldNotBeFound => _kindOf == _Kind.notFound;
  bool get couldNotBeReached => _kindOf == _Kind.unreachable;
  bool get stillToCheck => _kindOf == _Kind.notCheckedYet;

  /// One plain sentence for the person, or empty when there is nothing to say.
  /// Never an address and never an identifier.
  String get sayThis {
    final t = thing.isEmpty ? 'organisation' : thing;
    switch (_kindOf) {
      case _Kind.movedTo:
        return 'This $t has moved to a new address. This app checked that it '
            'is the same $t and switched to it.';
      case _Kind.notFound:
        return 'This app cannot find this $t where it expected. If it has '
            'moved, choose "find it again" and enter its new address, which '
            'whoever moved it can tell you.';
      case _Kind.unreachable:
        return 'This app cannot reach this $t right now. Check that this '
            'computer is online and that the machine it runs on is switched '
            'on. Nothing has been changed.';
      case _Kind.stillThere:
      case _Kind.notAFrontEnd:
      case _Kind.notCheckedYet:
        return '';
    }
  }

  /// Kept for callers that name the thing at the point of asking.
  String sayItAbout(String thing) =>
      WhereTheAgentWent._(_kindOf, origin, from, reasons, thing).sayThis;
}

enum _Kind {
  notAFrontEnd,
  notCheckedYet,
  stillThere,
  movedTo,
  notFound,
  unreachable
}
