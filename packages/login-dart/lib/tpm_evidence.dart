import 'dart:convert';
import 'dart:typed_data';

import 'installed_app.dart';

/// What a TPM gives for an app key once it has opened the Identity Agent's
/// credential: the key's public area, the AK's certify of it and signature, and
/// the secret the TPM released. All in the TCG wire form, as the TPM returns
/// them (`identity-agent-core/secureenclave/tpm_key_certify.go` reads them).
class TpmAttested {
  /// TPM2B_PUBLIC of the app key.
  final Uint8List keyPublic;

  /// The TPMS_ATTEST the AK signed (no size prefix).
  final Uint8List certifyInfo;

  /// TPMT_SIGNATURE over [certifyInfo].
  final Uint8List certifySignature;

  /// What TPM2_ActivateCredential released.
  final Uint8List credentialSecret;
  const TpmAttested(
      {required this.keyPublic,
      required this.certifyInfo,
      required this.certifySignature,
      required this.credentialSecret});
}

/// The evidence document the Identity Agent reads for a TPM key: the TPM's
/// parts with the endorsement certificate and attestation key the enrolment
/// named, byte fields in standard base64. Held to the core's own vectors
/// (`identity-agent-core/secureenclave/testdata/tpm_credential_exchange_*.json`),
/// made by a software TPM.
Uint8List tpmEvidence(TpmEnrolment enrolment, TpmAttested made) {
  String b(List<int> v) => base64.encode(v);
  return Uint8List.fromList(utf8.encode(jsonEncode({
    'key_public': b(made.keyPublic),
    'certify_info': b(made.certifyInfo),
    'certify_signature': b(made.certifySignature),
    'ak_public': b(enrolment.akPublic),
    'ek_cert': b(enrolment.ekCert),
    'ek_chain': [for (final c in enrolment.ekChain) b(c)],
    'credential_secret': b(made.credentialSecret),
  })));
}
