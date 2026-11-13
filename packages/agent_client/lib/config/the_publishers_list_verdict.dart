/// What the core said about a candidate bundle of the publisher's list of
/// accepted software (`POST /api/measurement-list`).
///
/// The core decides, and its answer is written for a person: [title] says what
/// is wrong in a sentence and [details] gives the reason. The app only chooses
/// what to do next from [kind], never from the words.
library;

enum MeasurementListVerdictKind {
  /// The list holds and is now the core's policy.
  accepted,

  /// The publisher's witnesses could not be asked just now: try again later.
  witnessesUnreachable,

  /// The bundle is older than what the witnesses hold: fetch a newer one.
  behind,

  /// The publisher's history conflicts with the one the core holds. The core
  /// keeps the evidence; nothing is accepted.
  conflict,

  /// This build trusts no publisher, so no list can be accepted at all.
  noPublisher,

  /// The list is not one the core accepts, for the reason in [details].
  refused,
}

class MeasurementListVerdict {
  final MeasurementListVerdictKind kind;
  final int? sequence;
  final String title;
  final String details;

  const MeasurementListVerdict(this.kind, {this.sequence, this.title = '', this.details = ''});

  bool get accepted => kind == MeasurementListVerdictKind.accepted;

  /// Whether another source of the bundle, or another try later, could help.
  bool get worthTryingAgain =>
      kind == MeasurementListVerdictKind.witnessesUnreachable || kind == MeasurementListVerdictKind.behind;

  static MeasurementListVerdict fromResponse(int status, Map<String, dynamic> body) {
    if (status == 200) {
      final seq = body['sequence'];
      return MeasurementListVerdict(MeasurementListVerdictKind.accepted, sequence: seq is int ? seq : null);
    }
    final title = (body['error'] ?? '').toString();
    final details = (body['details'] ?? body['detail'] ?? '').toString();
    final kind = switch (status) {
      503 => MeasurementListVerdictKind.witnessesUnreachable,
      409 when title.contains('trusts no publisher') => MeasurementListVerdictKind.noPublisher,
      409 when title.contains('older than') => MeasurementListVerdictKind.behind,
      409 => MeasurementListVerdictKind.conflict,
      _ => MeasurementListVerdictKind.refused,
    };
    return MeasurementListVerdict(kind, title: title, details: details);
  }
}
