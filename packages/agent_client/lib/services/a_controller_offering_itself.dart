import 'dart:convert';

import 'package:http/http.dart' as http;

import '../config/agent_config.dart';

/// A controller's signed, offline offer to act for an identity — the protocol
/// QR two of one person's own devices exchange.
///
/// A controller offer is NOT an Ask. An Ask is the rails for a transaction
/// between two DIFFERENT identities: a pointer fetched live from a relay, whose
/// scope is one identity asking something of another. This is two of the same
/// person's own devices meeting — there is no counterparty to fetch from and no
/// reason to be online, so the whole offer travels inside the QR, the same way
/// pairing a computer does (`grapeid://pair`). The scheme is what keeps it out
/// of the Ask engine, and the line is deliberate: anything internal and
/// device-to-device is a protocol QR, not an Ask.
///
/// It carries a signature, which the bare offer it replaces did not. A bare
/// offer was a public key and a claim anybody who photographed the screen could
/// present again — to a different owner, or after it went stale. The signature
/// binds the key to the agent it offers to act for and to the moment it was
/// made, so a captured code cannot be replayed to another agent or once it
/// ages, and the timestamp cannot be edited without breaking it. The owner's
/// device checks it (`POST /api/controller/verify-offer`) BEFORE the person is
/// asked to approve anything, and there is no unsigned path.
///
/// The signature is not what authorises the machine — the owner's grant does
/// that, and the agent refuses whatever the grant does not cover. It proves the
/// offer is fresh and really from the holder of the key it names, so the person
/// approves a live machine rather than a replayed or substituted claim.
class ControllerOffer {
  const ControllerOffer({
    required this.aid,
    required this.publicKey,
    required this.agentOrigin,
    required this.timestamp,
    required this.signature,
    this.protectedBy = '',
    this.label = '',
  });

  /// This machine's identifier, which IS its public key — the non-transferable
  /// form. The agent refuses a grant whose identifier and key disagree, so both
  /// travel and the far side checks rather than trusts.
  final String aid;
  final String publicKey;

  /// Which Identity Agent this machine offers to act for. Bound into the
  /// signature, so a captured offer cannot be aimed at a different one.
  final String agentOrigin;

  /// When the offer was made, RFC3339, bound into the signature. What makes a
  /// photographed code go stale.
  final String timestamp;

  /// Over [canonicalControllerOffer]'s bytes, by this machine's own key. The
  /// one field the bare offer lacked.
  final String signature;

  /// What is holding the private half — "Apple Secure Enclave" and so on. Shown
  /// to the person, because "this computer can keep a key to itself" is what
  /// makes authorising it reasonable at all. Not signed: it is a label, and the
  /// signature already proves the key is really held.
  final String protectedBy;

  /// What the machine suggests calling itself. A suggestion only, and the person
  /// names it — a machine that could write its own label into a device list
  /// could name itself something reassuring.
  final String label;

  static const scheme = 'grapeid';
  static const host = 'controller';

  /// Reads the core's signed-offer response into an offer.
  factory ControllerOffer.fromJson(Map<String, dynamic> m) => ControllerOffer(
        aid: (m['aid'] ?? '').toString(),
        publicKey: (m['public_key'] ?? '').toString(),
        agentOrigin: (m['agent_origin'] ?? '').toString(),
        timestamp: (m['timestamp'] ?? '').toString(),
        signature: (m['signature'] ?? '').toString(),
        protectedBy: (m['protected_by'] ?? '').toString(),
        label: (m['label'] ?? '').toString(),
      );

  /// The `grapeid://controller?…` link this offer shows as a QR.
  ///
  /// Every signed field is carried whole, because the owner's device rebuilds
  /// the exact string the core signed to check the signature — drop one and the
  /// check cannot run. Same scheme and shape as a pairing link, so the one Scan
  /// button routes it without a scanner of its own.
  String toScannableLink() {
    final q = <String, String>{
      'aid': aid,
      'key': publicKey,
      'agent': agentOrigin,
      'ts': timestamp,
      'sig': signature,
      if (protectedBy.isNotEmpty) 'protected_by': protectedBy,
      if (label.isNotEmpty) 'label': label,
    };
    return Uri(scheme: scheme, host: host, queryParameters: q).toString();
  }

  /// Reads an offer link, or returns null for anything that is not one.
  ///
  /// Null rather than an exception, the same as a pairing link: the one Scan
  /// button is pointed at whatever a camera sees, and the honest answer to most
  /// of that is "not one of ours". What IS one of ours but does not hold up — a
  /// stripped signature, a moved timestamp — is refused later by the core, not
  /// here; this reads only the shape.
  static ControllerOffer? parse(String raw) {
    final uri = Uri.tryParse(raw.trim());
    if (uri == null || uri.scheme != scheme || uri.host != host) return null;
    final aid = uri.queryParameters['aid'] ?? '';
    final key = uri.queryParameters['key'] ?? '';
    final agent = uri.queryParameters['agent'] ?? '';
    final ts = uri.queryParameters['ts'] ?? '';
    final sig = uri.queryParameters['sig'] ?? '';
    // The five signed fields are exactly what the signature covers; a link
    // missing any of them cannot be checked, so it is not an offer.
    if (aid.isEmpty ||
        key.isEmpty ||
        agent.isEmpty ||
        ts.isEmpty ||
        sig.isEmpty) {
      return null;
    }
    return ControllerOffer(
      aid: aid,
      publicKey: key,
      agentOrigin: agent,
      timestamp: ts,
      signature: sig,
      protectedBy: (uri.queryParameters['protected_by'] ?? '').trim(),
      label: (uri.queryParameters['label'] ?? '').trim(),
    );
  }

  /// The JSON body the verify route reads — the field names the core expects.
  Map<String, dynamic> toVerifyBody() => {
        'aid': aid,
        'public_key': publicKey,
        'agent_origin': agentOrigin,
        'timestamp': timestamp,
        'signature': signature,
        if (protectedBy.isNotEmpty) 'protected_by': protectedBy,
      };
}

/// Checks a scanned offer with the local core before the owner is asked to
/// approve it — the SOLE authentication of the offer, and mandatory.
///
/// Posted to THIS device's own core, not the agent: the check is pure crypto —
/// does the signature verify, is the offer fresh, does the identifier name the
/// key it publishes — and needs no state, so the device that scanned can answer
/// it without reaching the machine that made the offer. A missing, stale, or
/// unverifiable offer throws [ControllerOfferRefused]; there is no path that
/// shows the person a machine to approve without this passing.
Future<void> verifyControllerOffer(
  ControllerOffer offer, {
  http.Client? client,
  String? localCoreOrigin,
}) async {
  final core = localCoreOrigin ?? AgentConfig.coreBaseUrl;
  final c = client ?? http.Client();
  try {
    final res = await c.post(
      Uri.parse('$core/api/controller/verify-offer'),
      headers: const {'Content-Type': 'application/json'},
      body: jsonEncode(offer.toVerifyBody()),
    );
    if (res.statusCode == 200) return;
    // 422 is the core's considered "this offer does not hold up": stale,
    // repointed to another agent, unsigned, or naming a key its identifier does
    // not. Its detail is written for a person, so it is what the scanner shows.
    if (res.statusCode == 422) {
      throw ControllerOfferRefused(_reason(res.body));
    }
    throw ControllerOfferRefused(
        'this computer could not check that code (${res.statusCode})');
  } finally {
    if (client == null) c.close();
  }
}

/// The person-facing reason out of the core's error body, preferring the
/// specific detail over the headline. Falls back to the headline, then to a
/// plain sentence, so a body that does not parse still says something usable.
String _reason(String body) {
  try {
    final m = jsonDecode(body) as Map<String, dynamic>;
    final detail = (m['details'] ?? '').toString().trim();
    if (detail.isNotEmpty) return detail;
    final headline = (m['error'] ?? '').toString().trim();
    if (headline.isNotEmpty) return headline;
  } catch (_) {
    // Not JSON — fall through to the plain sentence.
  }
  return 'this offer could not be trusted';
}

/// A scanned controller offer that did not hold up. Its message is written for
/// a person, because the scanner shows it as "this code cannot be trusted".
class ControllerOfferRefused implements Exception {
  const ControllerOfferRefused(this.reason);
  final String reason;

  @override
  String toString() => reason;
}
