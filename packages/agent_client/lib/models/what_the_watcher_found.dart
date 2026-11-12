// What the Identity Agent's watcher found about the identities it has met, as
// the owner reads it. The shapes are the core's /api/watcher/* answers.

import 'dart:convert';
import 'package:crypto/crypto.dart';

/// Adding a contact was refused because the identity's key history forked: two
/// different histories were seen for the same event. [reason] is the core's
/// technical reason, for a log; a screen words the refusal itself.
class ContactRefusedForDuplicity implements Exception {
  final String aid;
  final String reason;
  const ContactRefusedForDuplicity({required this.aid, required this.reason});

  /// Reads a refusal body, or null when it is not a duplicity refusal.
  static ContactRefusedForDuplicity? fromResponse(int status, Map<String, dynamic> body) {
    if (status != 409 || body['code'] != 'duplicity') return null;
    return ContactRefusedForDuplicity(
      aid: (body['aid'] ?? '').toString(),
      reason: (body['details'] ?? '').toString(),
    );
  }

  /// What a person is told: what happened, what it means, what to do.
  String get plainMessage =>
      'This contact was not added. Two different versions of its key history '
      'were seen for the same step, which means the identity may have been copied '
      'or tampered with. Do not trust it. Ask the person to confirm who they are '
      'by another way you already trust, and to send you a fresh contact link.';

  @override
  String toString() => 'ContactRefusedForDuplicity($aid): $reason';
}

/// The agent has no watcher running. Said apart from "nothing found", so a
/// screen never reads off as all clear.
class WatcherNotRunning implements Exception {
  const WatcherNotRunning();
  @override
  String toString() => 'The watcher is not running on this agent.';
}

/// The two signed events at the place where an identity's key history forked.
/// Each is an event with its controller's signatures, so anyone can verify
/// either one without trusting this agent. [watcher] is the watcher that held
/// the rival.
class DuplicityEvidence {
  final int sequenceNumber;
  final String heldMessageB64;
  final String rivalMessageB64;
  final String watcher;

  const DuplicityEvidence({
    required this.sequenceNumber,
    required this.heldMessageB64,
    required this.rivalMessageB64,
    this.watcher = '',
  });

  /// True when both signed events are present. An older alert carries none.
  bool get hasBoth => heldMessageB64.isNotEmpty && rivalMessageB64.isNotEmpty;

  /// A short fingerprint of a signed event's bytes (the first 12 hex digits of
  /// its SHA-256), so a person can see the two differ. It names the bytes, not
  /// the event's own identifier, which only the event itself holds.
  static String fingerprint(String messageB64) {
    if (messageB64.isEmpty) return '';
    try {
      return sha256.convert(base64.decode(messageB64)).toString().substring(0, 12);
    } on FormatException {
      return '';
    }
  }

  String get heldFingerprint => fingerprint(heldMessageB64);
  String get rivalFingerprint => fingerprint(rivalMessageB64);

  /// Both signed events as one text a person can hand to someone who will
  /// verify them, with what each one is.
  String get copyText => [
        'Two signed events at place $sequenceNumber of one identity\'s key history.',
        if (watcher.isNotEmpty) 'The second was held by $watcher.',
        'Verify each against the history before place $sequenceNumber.',
        '',
        'Event held by this agent (base64):',
        heldMessageB64,
        '',
        'Rival event (base64):',
        rivalMessageB64,
      ].join('\n');

  static DuplicityEvidence? fromJson(Object? j) {
    if (j is! Map<String, dynamic> || j['kind'] != 'duplicity') return null;
    return DuplicityEvidence(
      sequenceNumber: (j['sequence_number'] ?? 0) as int,
      heldMessageB64: (j['held_message_b64'] ?? '').toString(),
      rivalMessageB64: (j['rival_message_b64'] ?? '').toString(),
      watcher: (j['watcher'] ?? '').toString(),
    );
  }
}

/// One alert the watcher raised. Never carries a digest.
///
/// [kind] is what the alert is about: "duplicity" (a proven fork: blocks the
/// contact until resolved), "escalation" (the standing watcher disagreed: shown,
/// blocks nothing) or "watcher" (a watcher's answer did not hold up: about the
/// watcher, never about the contact, and blocks nothing). An alert with no kind
/// is a duplicity alert.
class WatcherAlert {
  final int id;
  final String aid;
  final int sequenceNum;
  final String detectedAt;
  final bool acknowledged;
  final bool resolved;
  final String resolutionNote;
  final String kind;

  /// The watcher an alert concerns (for "duplicity" and "watcher"), else the source.
  final String sourceUrl;

  /// For a "duplicity" alert: the two signed events. Null on an older alert.
  final DuplicityEvidence? evidence;

  /// For a "watcher" alert: the sentence saying how its answer did not hold up.
  final String why;

  const WatcherAlert({
    required this.id,
    required this.aid,
    required this.sequenceNum,
    required this.detectedAt,
    this.acknowledged = false,
    this.resolved = false,
    this.resolutionNote = '',
    this.kind = 'duplicity',
    this.sourceUrl = '',
    this.evidence,
    this.why = '',
  });

  /// An alert stays one until it is resolved; acknowledging only records it was read.
  bool get isOpen => !resolved;

  /// Whether this alert is a watcher being flagged, not a contact being held.
  bool get isWatcherFlag => kind == 'watcher';

  /// Whether this alert blocks its contact until resolved: a proven fork only.
  bool get blocksContact => kind == 'duplicity';

  factory WatcherAlert.fromJson(Map<String, dynamic> j) {
    final ev = j['evidence'];
    final kind = (j['kind'] ?? '').toString();
    return WatcherAlert(
      id: (j['id'] ?? 0) as int,
      aid: j['aid'] ?? '',
      sequenceNum: (j['sequence_num'] ?? 0) as int,
      detectedAt: j['detected_at'] ?? '',
      acknowledged: j['acknowledged'] ?? false,
      resolved: j['resolved'] ?? false,
      resolutionNote: j['resolution_note'] ?? '',
      kind: kind.isEmpty ? 'duplicity' : kind,
      sourceUrl: (j['source_url'] ?? '').toString(),
      evidence: DuplicityEvidence.fromJson(ev),
      why: ev is Map<String, dynamic> && ev['kind'] == 'watcher' ? (ev['why'] ?? '').toString() : '',
    );
  }
}

/// What one source said in a check: "agrees", "disagrees", "no_answer",
/// "unreachable", "ahead" (it held later signed events, so the presented log
/// was stale and the agent went on with the latest), "behind" (an older branch
/// that a recovery rotation supersedes) or "faulty" (its answer did not hold up).
class WatcherSourceResult {
  final String type; // own_record | standing | hint | peer
  final String url;
  final String outcome;
  const WatcherSourceResult({required this.type, this.url = '', required this.outcome});

  factory WatcherSourceResult.fromJson(Map<String, dynamic> j) => WatcherSourceResult(
        type: j['type'] ?? '',
        url: j['url'] ?? '',
        outcome: j['outcome'] ?? '',
      );
}

/// The newest check of one identity. A contact with no [ContactWatchCheck] has
/// never been checked, which is not the same as one found sound.
class ContactWatchCheck {
  final String aid;
  final String checkedAt;
  final String verdict; // confirmed | duplicity | unreadable
  final String reason;
  final List<WatcherSourceResult> sources;

  const ContactWatchCheck({
    required this.aid,
    required this.checkedAt,
    required this.verdict,
    this.reason = '',
    this.sources = const [],
  });

  /// True only when a source other than this agent's own memory answered and
  /// agreed. A watcher that held the same history and later events ("ahead")
  /// agreed too: its signed log contains the history this contact showed.
  bool get anotherWatcherAgreed => sources.any(
      (s) => s.type != 'own_record' && (s.outcome == 'agrees' || s.outcome == 'ahead'));

  factory ContactWatchCheck.fromJson(Map<String, dynamic> j) => ContactWatchCheck(
        aid: j['aid'] ?? '',
        checkedAt: j['checked_at'] ?? '',
        verdict: j['verdict'] ?? '',
        reason: j['reason'] ?? '',
        sources: ((j['sources'] ?? const []) as List)
            .map((e) => WatcherSourceResult.fromJson(e as Map<String, dynamic>))
            .toList(),
      );
}

/// What the watcher is doing: [state] is "off", "own_record_only" (no watcher
/// is trusted, so only this agent's own memory can raise an alert) or "checking".
class WatcherStatus {
  final bool running;
  final String state;
  final String standingUrl;
  final List<String> shippedTrusted;
  final List<String> addedTrusted;
  final List<String> hints;
  final int openAlerts;

  /// Watchers flagged because their answer did not hold up, still open.
  final int openWatcherFlags;

  const WatcherStatus({
    required this.running,
    required this.state,
    this.standingUrl = '',
    this.shippedTrusted = const [],
    this.addedTrusted = const [],
    this.hints = const [],
    this.openAlerts = 0,
    this.openWatcherFlags = 0,
  });

  factory WatcherStatus.fromJson(Map<String, dynamic> j) {
    List<String> strings(Object? v) => ((v ?? const []) as List).map((e) => e.toString()).toList();
    return WatcherStatus(
      running: j['running'] ?? false,
      state: j['state'] ?? 'off',
      standingUrl: j['standing_url'] ?? '',
      shippedTrusted: strings(j['shipped_trusted']),
      addedTrusted: strings(j['added_trusted']),
      hints: strings(j['hints']),
      openAlerts: (j['open_alerts'] ?? 0) as int,
      openWatcherFlags: (j['open_watcher_flags'] ?? 0) as int,
    );
  }
}

/// What a contact's key history has been shown to be, in the words a contact
/// row uses. "Unchecked" is its own word: nothing was available to check the
/// history against, which is not the same as a history that failed.
String contactTrustLabel({required bool verified, required String status}) {
  if (verified) return 'Verified';
  return status == 'unchecked' ? 'Unchecked' : 'Unverified';
}

/// The identities with a duplicity alert still open: the ones a person sees as
/// Blocked. An escalation or a flagged watcher blocks nothing.
/// Resolving an alert is what clears it; reading it does not.
Set<String> aidsWithOpenAlerts(Iterable<WatcherAlert> alerts) =>
    {for (final a in alerts) if (a.isOpen && a.blocksContact) a.aid};
