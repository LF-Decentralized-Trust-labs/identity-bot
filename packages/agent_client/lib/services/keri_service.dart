enum AgentEnvironment {
  desktop,
  mobileStandalone,
  mobileRemoteWithKeys,
  mobileRemoteWithoutKeys,
}

class InceptionResult {
  final String aid;
  final String publicKey;
  final String kel;
  final String created;
  // cesrSignature: the signature over the inception event body, indexed (AA...,
  // 88 chars) at place 0, as a signature on a key event is.
  // Empty string if it was not written (mobile stub path).
  final String cesrSignature;
  // rawBytesB64: the inception event bytes that were signed (base64).
  final String rawBytesB64;
  // The witnesses the founding names, and how many must receipt it.
  final List<String> witnesses;
  final int witnessThreshold;
  // Why the founding names no witness, where it names none; null otherwise.
  // An identity founded this way has nothing but its core's copy of its log to
  // corroborate it, and its key state is read as uncorroborated.
  final String? unwitnessedBecause;

  InceptionResult({
    required this.aid,
    required this.publicKey,
    required this.kel,
    required this.created,
    this.cesrSignature = '',
    this.rawBytesB64 = '',
    this.witnesses = const [],
    this.witnessThreshold = 0,
    this.unwitnessedBecause,
  });
}

class RotationResult {
  final String aid;
  final String newPublicKey;
  final String kel;
  final String cesrSignature;

  RotationResult({
    required this.aid,
    required this.newPublicKey,
    required this.kel,
    this.cesrSignature = '',
  });
}

class SignatureResult {
  // signature: raw Ed25519 signature, base64-encoded.
  final String signature;
  final String publicKey;
  // cesrSignature: the same signature unindexed (0B..., 88 chars), as the core's
  // /api/verify reads it against [publicKey]. Empty string if it was not written.
  final String cesrSignature;

  SignatureResult({
    required this.signature,
    required this.publicKey,
    this.cesrSignature = '',
  });
}

class InteractResult {
  final String aid;
  final String said;
  final int sequenceNumber;
  // cesrSignature: the signature over the IXN event body, indexed (AA...) at
  // place 0, as a signature on a key event is.
  final String cesrSignature;

  InteractResult({
    required this.aid,
    required this.said,
    required this.sequenceNumber,
    this.cesrSignature = '',
  });
}

class PresentationResult {
  final String presentationSaid;
  final String presentationJsonB64;
  // cesrSignature: the signature over the presentation SAID bytes, unindexed
  // (0B...), as the core's /api/credential/verify reads it. Proves the holder
  // possesses the key bound to the holder AID in the credential.
  final String cesrSignature;

  PresentationResult({
    required this.presentationSaid,
    required this.presentationJsonB64,
    this.cesrSignature = '',
  });
}

class CredentialIssuanceResult {
  final String acdcSaid;
  final String acdcJsonB64;
  // ixnRawBytesB64: the IXN event bytes the controller signs to anchor the credential.
  final String ixnRawBytesB64;
  final String ixnSaid;
  final int sequenceNumber;
  // cesrSignature: the signature over the IXN event body, indexed (AA...) at
  // place 0, as a signature on a key event is. Empty until Dart signs.
  final String cesrSignature;

  CredentialIssuanceResult({
    required this.acdcSaid,
    required this.acdcJsonB64,
    required this.ixnRawBytesB64,
    required this.ixnSaid,
    required this.sequenceNumber,
    this.cesrSignature = '',
  });
}

class WitnessReceiptResult {
  final bool accepted;
  final bool thresholdMet;
  final int receiptCount;
  final List<String> errors;

  WitnessReceiptResult({
    required this.accepted,
    required this.thresholdMet,
    required this.receiptCount,
    this.errors = const [],
  });
}

/// An identity's key event log as the core serves it.
///
/// [events] are the parsed events, oldest first, and [rawEventsB64] the bytes
/// each was published as, in base64. Anything that checks a signature or
/// recomputes an identifier must use the bytes: field order is part of an
/// event, and re-serialising the parsed form produces something that verifies
/// as nothing. An entry is empty where the core did not keep the bytes.
class KeyEventLog {
  final String aid;
  final List<Map<String, dynamic>> events;
  final List<String> rawEventsB64;
  final int sequenceNumber;
  final int eventCount;

  /// Whether the core holds a signature over each event, beside [events]; null
  /// from a core that does not say.
  final List<bool>? signed;

  KeyEventLog({
    required this.aid,
    required this.events,
    required this.rawEventsB64,
    required this.sequenceNumber,
    required this.eventCount,
    this.signed,
  });

  /// Reads the core's GET /api/kel answer. Throws for an answer that names no
  /// identifier or carries no list of events: an empty log read from a broken
  /// answer would look like an identity with no history.
  factory KeyEventLog.fromJson(Map<String, dynamic> json) {
    final aid = json['aid'];
    final kel = json['kel'];
    if (aid is! String || aid.isEmpty || kel is! List) {
      throw const FormatException('the core\'s answer is not a key log: it names no identifier or no events');
    }
    final signed = json['signed'];
    return KeyEventLog(
      aid: aid,
      events: [
        for (final e in kel)
          if (e is Map) Map<String, dynamic>.from(e),
      ],
      rawEventsB64: [
        for (final r in json['raw_events_b64'] as List? ?? const []) r is String ? r : '',
      ],
      sequenceNumber: json['sequence_number'] as int? ?? 0,
      eventCount: json['event_count'] as int? ?? 0,
      signed: signed is List && signed.length == kel.length ? [for (final b in signed) b == true] : null,
    );
  }

  /// The events that set the identity's keys (founding and rotations), oldest
  /// first. The last one names the key in force.
  List<Map<String, dynamic>> get establishmentEvents => [
        for (final e in events)
          if (const {'icp', 'dip', 'rot', 'drt'}.contains(e['t'])) e,
      ];
}

class KerlEntry {
  final String eventSaid;
  final List<Map<String, dynamic>> receipts;
  final int receiptCount;
  final bool thresholdMet;

  KerlEntry({
    required this.eventSaid,
    required this.receipts,
    required this.receiptCount,
    required this.thresholdMet,
  });
}

class VerificationResult {
  final bool verified;
  // checks: map of check name → bool (e.g. "said_integrity": true).
  final Map<String, dynamic> checks;
  final List<String> errors;
  final String acdcSaid;

  VerificationResult({
    required this.verified,
    required this.checks,
    required this.errors,
    required this.acdcSaid,
  });
}

abstract class KeriService {
  AgentEnvironment get environment;

  Future<InceptionResult> inceptAid({
    required String name,
    required String code,
  });

  Future<RotationResult> rotateAid({required String name});

  /// Create a KERI interaction (IXN) event anchoring [sealData] in the KEL.
  /// [sealData] is a list of seal maps, e.g. [{"d": "<credentialSAID>"}].
  Future<InteractResult> interactAid({
    required String name,
    List<Map<String, String>> sealData,
  });

  Future<SignatureResult> signPayload({
    required String name,
    required List<int> data,
  });

  Future<KeyEventLog> getCurrentKel({
    required String name,
  });

  Future<bool> verifySignature({
    required List<int> data,
    required String signature,
    required String publicKey,
  });

  Future<CredentialIssuanceResult> issueCredential({
    required Map<String, dynamic> claims,
    required String schemaSaid,
    String holderAid = '',
    String name = '',
  });

  Future<PresentationResult> presentCredential({
    required String acdcSaid,
    required String holderAid,
    String issuerAid = '',
    String schemaSaid = '',
  });

  /// Submit a witness receipt for one of this identity's own KERI events. The
  /// receipt is a CESR-encoded Ed25519 signature from a witness over the event
  /// SAID (UTF-8 bytes). It is checked against the witness identifier, which is
  /// the witness's key, and counted against the designated witnesses and
  /// threshold in this identity's own key log.
  Future<WitnessReceiptResult> submitWitnessReceipt({
    required String eventSaid,
    required String witnessAid,
    required String cesrSignature,
  });

  /// Retrieve the KERL entry for an event: the event SAID plus all
  /// accumulated witness receipts and threshold status.
  Future<KerlEntry> getKERL({
    required String eventSaid,
    int threshold = 0,
  });

  /// Verify a credential against the 8-check engine:
  /// SAID integrity, issuer KEL, KEL hash chain, schema trust,
  /// revocation, holder subject match, presentation sig, IXN anchor.
  Future<VerificationResult> verifyCredential({
    required String acdcJson,
    String holderAid = '',
    String presentationSaid = '',
    String cesrSignature = '',
    String holderPublicKey = '',
    List<String> trustedSchemaSaids = const [],
  });

  void dispose();
}
