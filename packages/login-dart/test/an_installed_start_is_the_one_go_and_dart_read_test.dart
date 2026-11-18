import 'dart:convert';
import 'dart:io';

import 'package:login_dart/app_checks.dart';
import 'package:login_dart/installed_app.dart';
import 'package:test/test.dart';

// The statement an installed front end's key signs, the thumbprint that names the
// key and the start body it sends are held to
// ../login-web/test-vectors/installed-app.json, which login-go (and the Identity
// Agent's own InstalledAppSignInStatement) read alike.
final v = jsonDecode(
        File('../login-web/test-vectors/installed-app.json').readAsStringSync())
    as Map<String, dynamic>;

List<Map<String, dynamic>> of(String k) =>
    (v[k] as List).cast<Map<String, dynamic>>();

void main() {
  test('the statement the key signs, and its digest, are the shared ones', () {
    for (final c in of('statement')) {
      final ch = b64uDecode(c['challenge_b64u'] as String)!;
      final t = c['thumbprint'] as String, a = c['asset_id'] as String;
      expect(installedAppStatement(a, ch, t), c['text']);
      expect(
          installedAppStatementDigest(a, ch, t)
              .map((b) => b.toRadixString(16).padLeft(2, '0'))
              .join(),
          c['sha256_hex']);
    }
  });

  test('a key is named by the shared thumbprint', () {
    for (final c in of('thumbprint')) {
      expect(browserKeyThumbprint(c['x'] as String, c['y'] as String),
          c['thumbprint']);
    }
  });

  test('the start body this side writes is one the shared cases accept', () {
    final ok = of('starts').firstWhere((c) => c['expect'] == 'installed_app');
    final j = jsonDecode(ok['body'] as String) as Map<String, dynamic>;
    final p = j['proof'] as Map<String, dynamic>;
    final mine = frontEndStartBody(
        kind: FrontEndKind.installedApp,
        jwk: (j['jwk'] as Map).cast<String, String>(),
        thumbprint: j['browserKey'] as String,
        proof: InstalledKeyProof(
            platform: p['platform'] as String,
            evidence: base64.decode(p['evidence'] as String),
            ask: p['ask'] as String,
            keySignature: base64.decode(p['key_signature'] as String)));
    expect(jsonDecode(mine), j);
  });

  test('what Go refuses, this side will not write', () {
    final jwk = {'kty': 'EC', 'crv': 'P-256', 'x': 'x', 'y': 'y'};
    expect(
        () => frontEndStartBody(
            kind: FrontEndKind.installedApp, jwk: jwk, thumbprint: 't'),
        throwsArgumentError);
    final proof = InstalledKeyProof(
        platform: 'android',
        evidence: base64.decode('ZXZpZGVuY2U='),
        ask: 'a',
        keySignature: base64.decode('c2ln'));
    expect(
        () => frontEndStartBody(
            kind: FrontEndKind.browser,
            jwk: jwk,
            thumbprint: 't',
            proof: proof),
        throwsArgumentError);
  });
}
