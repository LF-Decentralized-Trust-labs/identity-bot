// What the Identity Agent's watcher found about the identities it has met, as
// the owner reads it. The shapes are the core's /api/watcher/* answers.

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

/// One alert the watcher raised. Never carries a digest.
class WatcherAlert {
  final int id;
  final String aid;
  final int sequenceNum;
  final String detectedAt;
  final bool acknowledged;
  final bool resolved;
  final String resolutionNote;

  const WatcherAlert({
    required this.id,
    required this.aid,
    required this.sequenceNum,
    required this.detectedAt,
    this.acknowledged = false,
    this.resolved = false,
    this.resolutionNote = '',
  });

  /// An alert stays one until it is resolved; acknowledging only records it was read.
  bool get isOpen => !resolved;

  factory WatcherAlert.fromJson(Map<String, dynamic> j) => WatcherAlert(
        id: (j['id'] ?? 0) as int,
        aid: j['aid'] ?? '',
        sequenceNum: (j['sequence_num'] ?? 0) as int,
        detectedAt: j['detected_at'] ?? '',
        acknowledged: j['acknowledged'] ?? false,
        resolved: j['resolved'] ?? false,
        resolutionNote: j['resolution_note'] ?? '',
      );
}

/// What one source said in a check: "agrees", "disagrees", "no_answer" or "unreachable".
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

  /// True only when a source other than this agent's own memory answered and agreed.
  bool get anotherWatcherAgreed =>
      sources.any((s) => s.type != 'own_record' && s.outcome == 'agrees');

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

  const WatcherStatus({
    required this.running,
    required this.state,
    this.standingUrl = '',
    this.shippedTrusted = const [],
    this.addedTrusted = const [],
    this.hints = const [],
    this.openAlerts = 0,
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

/// The identities with an alert still open: the ones a person sees as Blocked.
/// Resolving an alert is what clears it; reading it does not.
Set<String> aidsWithOpenAlerts(Iterable<WatcherAlert> alerts) =>
    {for (final a in alerts) if (a.isOpen) a.aid};
