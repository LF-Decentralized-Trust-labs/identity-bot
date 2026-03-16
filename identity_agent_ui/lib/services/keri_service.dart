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
  // cesrSignature: CESR '0B...' (88-char) signature over the inception event body.
  // Empty string if CESR encoding is not yet available (mobile stub path).
  final String cesrSignature;
  // rawBytesB64: the inception event bytes that were signed (base64).
  final String rawBytesB64;

  InceptionResult({
    required this.aid,
    required this.publicKey,
    required this.kel,
    required this.created,
    this.cesrSignature = '',
    this.rawBytesB64 = '',
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
  // cesrSignature: CESR '0B...' (88-char) encoding of the same signature.
  // Empty string if CESR encoding was not requested.
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
  // cesrSignature: CESR '0B...' signature over the IXN event body.
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
  // cesrSignature: CESR '0B...' signature over the presentation SAID bytes.
  // Proves the holder possesses the key bound to the holder AID in the credential.
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
  // cesrSignature: CESR '0B...' signature over the IXN event body. Empty until Dart signs.
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

  Future<String> getCurrentKel({
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
