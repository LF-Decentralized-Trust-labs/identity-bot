import 'package:flutter/foundation.dart';

/// Where a computer is and the code it is showing, read out of a scanned link.
@immutable
class PairingInvitation {
  const PairingInvitation({
    required this.host,
    required this.code,
    this.kind = 'individual',
    this.ownerAid = '',
    this.reportTo = '',
  });

  final String host;
  final String code;

  /// The identity this machine has ALREADY been told may claim it, when
  /// somebody said so before the machine existed.
  ///
  /// A machine asked for in advance is told who may claim it as it is created —
  /// that is what stops whoever reaches it first from taking it — and it is told
  /// once, permanently. So the app that claims it does not get to choose an
  /// identity: it has to sign as the one already named, or the machine refuses
  /// the claim as coming from somebody else.
  ///
  /// Empty for a computer offering itself from its own screen. Nobody has named
  /// an owner there yet, and the app that scans the screen mints one and says
  /// so as part of claiming it.
  final String ownerAid;

  /// Where to tell the app that started this what was founded, once it exists.
  ///
  /// Empty for everything but an organisation. The app driving a founding
  /// cannot read the identity it made — that route is owner-only and it holds
  /// public halves — so this app, which does get an answer, says what it was.
  /// The arrow D4b draws.
  ///
  /// Carrying an address does not make it trusted. Nothing is sent anywhere
  /// until the machine has confirmed what was founded, and the receiving app
  /// asks that machine again before believing it.
  final String reportTo;

  /// What is being asked of you.
  ///
  /// `individual` — be the owner of this computer, and let it be your always-on
  /// one. `organisation` — be a signer and owner of this organisation.
  ///
  /// The ceremony is identical either way and the machine is never told which;
  /// it founds its own root and seals in an owner regardless. This exists so
  /// the person is asked the right question and so what they end up owning is
  /// filed under the right heading afterwards.
  final String kind;

  /// Whether this ask is to become an owner of an organisation.
  bool get isOrganisation => kind == 'organisation';

  /// The neutral scheme the protocol emits and recognises.
  ///
  /// Named for the protocol rather than a vendor: these codes are the wire
  /// namespace, and a brand here would make the neutral core emit branded links
  /// and force an independent implementation to speak a vendor's token to
  /// interoperate. A downstream build MAY override the scheme it displays for
  /// its own registered handler; the neutral name is what is emitted here, and
  /// it is a single constant so an override is one substitution.
  static const scheme = 'identity-agent';

  /// Builds the link a computer shows, so no caller has to spell the scheme.
  ///
  /// One place emits the string, which is what keeps every emitter neutral at
  /// once and stops the four of them drifting into four spellings of the same
  /// link. `kind`, `owner` and `report` are carried only when they say
  /// something — a plain computer pairing omits all three.
  static String link({
    required String host,
    required String code,
    String kind = 'individual',
    String ownerAid = '',
    String reportTo = '',
  }) {
    final buf = StringBuffer('$scheme://pair'
        '?host=${Uri.encodeComponent(host)}'
        '&code=${Uri.encodeComponent(code)}');
    if (kind != 'individual') {
      buf.write('&kind=${Uri.encodeComponent(kind)}');
    }
    if (ownerAid.isNotEmpty) {
      buf.write('&owner=${Uri.encodeComponent(ownerAid)}');
    }
    if (reportTo.isNotEmpty) {
      buf.write('&report=${Uri.encodeComponent(reportTo)}');
    }
    return buf.toString();
  }

  /// Reads an invitation, or returns null for anything that is not one.
  ///
  /// Null rather than an exception, and rather than a guess. A camera picks up
  /// whatever is in front of it — a shop's wifi poster, somebody's website —
  /// and the honest answer to most of what it sees is "that is not one of ours".
  static PairingInvitation? parse(String raw) {
    final uri = Uri.tryParse(raw.trim());
    if (uri == null || uri.scheme != scheme || uri.host != 'pair') {
      return null;
    }
    final host = uri.queryParameters['host'] ?? '';
    final code = uri.queryParameters['code'] ?? '';
    if (host.isEmpty || code.isEmpty) return null;
    // An ask nobody recognises is refused rather than treated as the default.
    // Guessing 'a computer' would file an organisation under somebody's
    // machines, and nothing afterwards disagrees with that.
    final kind = uri.queryParameters['kind'] ?? 'individual';
    if (kind != 'individual' && kind != 'organisation') return null;
    // A host that is not an address is not something to go and talk to.
    final target = Uri.tryParse(host);
    if (target == null || !target.hasScheme || target.host.isEmpty) return null;
    // Optional, and safe to carry. It is a pairwise identifier that the machine
    // will name in its own seal the moment it is claimed, so a link is not where
    // it becomes public. An identity the scanning device never minted is refused
    // at the claim, so a forged one costs a refusal rather than a machine.
    final owner = (uri.queryParameters['owner'] ?? '').trim();
    // Optional. An address that is not one is dropped rather than refusing the
    // whole invitation: failing to report back costs an identifier on somebody
    // else's screen, and refusing here would cost them the organisation.
    var report = (uri.queryParameters['report'] ?? '').trim();
    final reportUri = report.isEmpty ? null : Uri.tryParse(report);
    if (reportUri == null || !reportUri.hasScheme || reportUri.host.isEmpty) {
      report = '';
    }
    return PairingInvitation(
        host: host, code: code, kind: kind, ownerAid: owner, reportTo: report);
  }
}
