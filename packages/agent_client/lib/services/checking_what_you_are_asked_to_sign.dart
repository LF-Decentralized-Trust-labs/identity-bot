import 'dart:convert';

import 'package:http/http.dart' as http;

/// Checking a grant another Identity Agent asks this device to sign.
///
/// This device holds the identity's key. An Identity Agent that does not, a
/// desktop or a server, asks it to sign the interaction that anchors a grant:
/// a machine allowed to act, or an AI agent allowed to do things. That agent's
/// database may be writable by somebody else, so nothing it wrote about the
/// grant is shown here. The request carries the credential, its issuance event
/// and the interaction, and this device's OWN core checks that the interaction
/// anchors exactly that issuance of exactly that credential, and that it
/// extends this identity's key log as this device holds it. What is shown is
/// read from the credential: who it grants, the machine's key and its
/// fingerprint (compare it with the one shown when the machine paired), the
/// signer, the end, the capabilities.
///
/// Sign only what [check] returns, and show only what it returns. If it
/// throws, do not sign.
class CheckingWhatYouAreAskedToSign {
  CheckingWhatYouAreAskedToSign({
    required this.ownOrigin,
    required http.Client client,
  }) : _client = client;

  /// This device's own core: never the Identity Agent that asked.
  final String ownOrigin;

  /// Signs as the owner of this device's core.
  final http.Client _client;

  Future<WhatSigningGrants> check(AskedToSign request) async {
    final res = await _client.post(
      Uri.parse('$ownOrigin/api/signing-requests/check'),
      headers: const {'Content-Type': 'application/json'},
      body: jsonEncode({
        'payload_b64': request.payloadB64,
        if (request.credentialB64 != null)
          'credential_b64': request.credentialB64,
        if (request.issuanceB64 != null) 'issuance_b64': request.issuanceB64,
        if (request.registryB64 != null) 'registry_b64': request.registryB64,
      }),
    );
    if (res.statusCode != 200) {
      throw NotSafeToSign(res.statusCode, res.body);
    }
    return WhatSigningGrants.fromJson(
        jsonDecode(res.body) as Map<String, dynamic>);
  }
}

/// A grant, or a registry, another Identity Agent asks this device to sign,
/// as its signing-request queue lists it.
class AskedToSign {
  const AskedToSign({
    required this.id,
    required this.kind,
    required this.payloadB64,
    this.credentialB64,
    this.issuanceB64,
    this.registryB64,
  });

  final String id;

  /// "grant-issuance" or "registry-inception".
  final String kind;

  /// Exactly what is signed: the interaction.
  final String payloadB64;
  final String? credentialB64;
  final String? issuanceB64;
  final String? registryB64;

  /// Whether this is a request this checker is for.
  bool get isAGrant => kind == 'grant-issuance' || kind == 'registry-inception';

  factory AskedToSign.fromJson(Map<String, dynamic> m) => AskedToSign(
        id: (m['id'] ?? '').toString(),
        kind: (m['kind'] ?? '').toString(),
        payloadB64: (m['payload_b64'] ?? '').toString(),
        credentialB64: m['credential_b64'] as String?,
        issuanceB64: m['issuance_b64'] as String?,
        registryB64: m['registry_b64'] as String?,
      );
}

/// What signing grants, read from the credential itself.
class WhatSigningGrants {
  const WhatSigningGrants({
    required this.kind,
    required this.issuer,
    required this.sn,
    required this.prior,
    this.holder = '',
    this.name = '',
    this.publicKey = '',
    this.keyFingerprint = '',
    this.grade = '',
    this.signer = '',
    this.validUntil = '',
    this.capabilities = const [],
  });

  /// "machine", "ai_agent" or "registry".
  final String kind;
  final String issuer;
  final int sn;
  final String prior;
  final String holder;
  final String name;
  final String publicKey;

  /// Compare with the fingerprint shown when the machine paired.
  final String keyFingerprint;
  final String grade;
  final String signer;
  final String validUntil;
  final List<String> capabilities;

  factory WhatSigningGrants.fromJson(Map<String, dynamic> m) =>
      WhatSigningGrants(
        kind: (m['kind'] ?? '').toString(),
        issuer: (m['issuer'] ?? '').toString(),
        sn: (m['sn'] as num?)?.toInt() ?? -1,
        prior: (m['prior'] ?? '').toString(),
        holder: (m['holder'] ?? '').toString(),
        name: (m['name'] ?? '').toString(),
        publicKey: (m['public_key'] ?? '').toString(),
        keyFingerprint: (m['key_fingerprint'] ?? '').toString(),
        grade: (m['grade'] ?? '').toString(),
        signer: (m['signer'] ?? '').toString(),
        validUntil: (m['valid_until'] ?? '').toString(),
        capabilities: ((m['capabilities'] as List?) ?? const [])
            .map((c) => c.toString())
            .toList(),
      );
}

/// This device's core would not vouch for what it was asked to sign.
class NotSafeToSign implements Exception {
  NotSafeToSign(this.status, this.body);
  final int status;
  final String body;
  @override
  String toString() => 'not safe to sign ($status): $body';
}
