import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:login_dart/app_checks.dart';
import 'package:login_dart/apple_attest.dart';
import 'package:login_dart/front_end_key.dart';
import 'package:login_dart/installed_app.dart';
import 'package:test/test.dart';

// An App Attest key signs only assertions: the key is read from its attestation
// object, and the proof of each call is the assertion itself (never converted as a
// DER signature is). The assertion is held to the vector login-go and the Identity
// Agent's own checker verify.

List<int> bytes(int n, int v) => List<int>.filled(n, v);

/// CBOR: a byte string / text string / map header for the sizes used here.
List<int> cb(List<int> b) => [0x58, b.length, ...b];
List<int> ct(String s) => [0x60 | s.length, ...s.codeUnits];

Uint8List attestation(List<int> x, List<int> y, {int idLen = 32}) {
  final cose = [
    0xa5,
    0x01,
    0x02,
    0x03,
    0x26,
    0x20,
    0x01,
    0x21,
    ...cb(x),
    0x22,
    ...cb(y)
  ];
  final auth = [
    ...bytes(32, 1),
    0x45,
    0,
    0,
    0,
    0,
    ...bytes(16, 2),
    0,
    idLen,
    ...bytes(idLen, 3),
    ...cose
  ];
  return Uint8List.fromList([
    0xa2,
    ...ct('fmt'),
    ...ct('apple-appattest'),
    ...ct('authData'),
    0x59,
    0,
    auth.length,
    ...auth
  ]);
}

class _Apple implements HardwareKeyPlatform {
  final Uint8List assertion;
  _Apple(this.assertion);
  @override
  String get platform => InstalledPlatform.apple;
  @override
  bool get callProofIsAssertion => true;
  @override
  Future<Uint8List?> publicPoint(String label) async => null;
  @override
  Future<Uint8List> signCall(String label, Uint8List message) async =>
      assertion;
  @override
  Future<({Uint8List point, Uint8List evidence})> attestNewKey(
      String label, Uint8List challenge) async {
    final e = attestation(bytes(32, 5), bytes(32, 6));
    return (point: appleAttestedPoint(e), evidence: e);
  }

  @override
  Future<Uint8List> signStatement(String label, Uint8List d) async => assertion;
}

void main() {
  test('the key is the point the attestation object carries', () {
    final p = appleAttestedPoint(attestation(bytes(32, 5), bytes(32, 6)));
    expect(p.length, 65);
    expect(p[0], 4);
    expect(p.sublist(1, 33), bytes(32, 5));
    expect(p.sublist(33), bytes(32, 6));
  });

  test('what is not an App Attest object is refused', () {
    for (final bad in [
      Uint8List(0),
      Uint8List.fromList([0xa0]),
      Uint8List.fromList([1, 2, 3]),
      attestation(bytes(31, 5), bytes(32, 6)).sublist(0, 40),
    ]) {
      expect(() => appleAttestedPoint(bad), throwsA(anything));
    }
    expect(() => appleAttestedPoint(attestation(bytes(32, 5), bytes(31, 6))),
        throwsA(anything));
  });

  test(
      'a call is proved by the assertion as it is, not converted like a DER signature',
      () async {
    final v = jsonDecode(File('../login-web/test-vectors/installed-app.json')
        .readAsStringSync()) as Map<String, dynamic>;
    final hex = (v['apple_assertion'] as Map)['assertion_hex'] as String;
    final assertion = Uint8List.fromList([
      for (var i = 0; i < hex.length; i += 2)
        int.parse(hex.substring(i, i + 2), radix: 16)
    ]);
    final key = await HardwareFrontEndKey.open(_Apple(assertion), 'k');
    expect(() => key.thumbprint, throwsStateError,
        reason: 'no key exists until one is made for an ask');
    await key.prove('Eapp', InstalledAsk('a', b64uEncode(bytes(32, 9)), 'x'));
    expect(key.x, b64uEncode(bytes(32, 5)));
    expect(b64uDecode(await key.sign('IABK1\nGET\n/x')), assertion);
  });
}
