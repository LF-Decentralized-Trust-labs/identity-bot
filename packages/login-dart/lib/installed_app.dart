import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' show SHA256Digest;

import 'app_checks.dart';

/// An installed front end's sign-in start (ADR-072 section 2 step 4,
/// Amendment 3), the Dart side of `packages/login-go/installed_app.go`, held to
/// `../login-web/test-vectors/installed-app.json`, which Go runs too.

enum FrontEndKind {
  browser('browser'),
  installedApp('installed_app');

  final String wire;
  const FrontEndKind(this.wire);
}

/// The platforms that can vouch for an installed front end's key.
abstract class InstalledPlatform {
  static const android = 'android';
  static const apple = 'apple';
  static const tpm = 'tpm';
}

/// Where an installed front end asks its back end for an ask (a sealed call).
const installedAskPath = '/signin/installed-key/ask';

/// What the back end hands an installed front end to make evidence for.
class InstalledAsk {
  final String ask;

  /// The utility app's asset, which the key's statement names (only the back end
  /// knows it: the app's identifier a link carries is another name).
  final String assetId;

  /// Unpadded base64url of the challenge bytes the hardware attests.
  final String challenge;
  final String expires;
  const InstalledAsk(this.ask, this.assetId, this.challenge, this.expires);

  factory InstalledAsk.fromJson(Object? j) {
    if (j is! Map ||
        j['ask'] is! String ||
        (j['ask'] as String).isEmpty ||
        j['asset_id'] is! String ||
        (j['asset_id'] as String).isEmpty ||
        j['challenge'] is! String ||
        b64uDecode(j['challenge']) == null ||
        j['expires'] is! String) {
      throw const TrustRefused('the app\'s ask for evidence is not readable');
    }
    return InstalledAsk(j['ask'] as String, j['asset_id'] as String,
        j['challenge'] as String, j['expires'] as String);
  }
}

/// The hardware's evidence for a key, on the wire as the Identity Agent reads it:
/// the byte fields are standard base64.
class InstalledKeyProof {
  final String platform;
  final Uint8List evidence;
  final String ask;
  final Uint8List keySignature;
  const InstalledKeyProof(
      {required this.platform,
      required this.evidence,
      required this.ask,
      required this.keySignature});

  Map<String, Object> toJson() => {
        'platform': platform,
        'evidence': base64.encode(evidence),
        'ask': ask,
        'key_signature': base64.encode(keySignature),
      };
}

/// What an installed front end's key signs to start a sign-in: the app's asset,
/// the ask's challenge and the key's own thumbprint.
String installedAppStatement(
        String assetId, List<int> challenge, String keyThumbprint) =>
    'identity-agent installed-app sign-in v1\n$assetId\n${b64uEncode(challenge)}\n$keyThumbprint';

/// The SHA-256 the key signs (Apple's App Attest takes it as its client data hash).
Uint8List installedAppStatementDigest(
        String assetId, List<int> challenge, String keyThumbprint) =>
    SHA256Digest().process(Uint8List.fromList(
        utf8.encode(installedAppStatement(assetId, challenge, keyThumbprint))));

/// The body of the call that starts a sign-in for a front end's key. An installed
/// app's carries [proof]; a browser's never does.
String frontEndStartBody(
    {required FrontEndKind kind,
    required Map<String, String> jwk,
    required String thumbprint,
    InstalledKeyProof? proof}) {
  if ((kind == FrontEndKind.installedApp) != (proof != null)) {
    throw ArgumentError(kind == FrontEndKind.installedApp
        ? 'an installed app\'s sign-in needs the hardware\'s evidence'
        : 'a browser\'s sign-in carries no hardware proof');
  }
  return jsonEncode({
    'frontEnd': kind.wire,
    'browserKey': thumbprint,
    'jwk': jwk,
    if (proof != null) 'proof': proof.toJson(),
  });
}
