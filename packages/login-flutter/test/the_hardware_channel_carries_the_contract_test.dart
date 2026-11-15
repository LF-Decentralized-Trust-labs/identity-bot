import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:login_dart/front_end_key.dart';
import 'package:login_dart/installed_app.dart';
import 'package:login_flutter/login_flutter.dart';

// The Dart half of the contract with each platform's hardware code: the four
// calls, their arguments and what they must give back, held against a fake channel
// that answers as android/.../HardwareKey.kt does. It does not show that any hardware
// does so; see the README's "Not built".

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('t');
  final calls = <MethodCall>[];
  final point = Uint8List.fromList(
      [4, ...List<int>.filled(32, 1), ...List<int>.filled(32, 2)]);

  setUp(() {
    calls.clear();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (c) async {
      calls.add(c);
      switch (c.method) {
        case 'publicPoint':
          return point;
        case 'attestNewKey':
          return {
            'point': point,
            'evidence': Uint8List.fromList([9, 9])
          };
        case 'signCall':
        case 'signStatement':
          return Uint8List.fromList([0x30, 6, 2, 1, 1, 2, 1, 1]);
      }
      return null;
    });
  });

  test('the key is opened, signs, and is made again for an ask', () async {
    final hw = MethodChannelHardwareKey(
        channel: channel, platform: InstalledPlatform.android);
    final key = await HardwareFrontEndKey.open(hw, 'k');
    expect(key.x.length, 43);
    expect(await key.sign('m'), isNotEmpty);
    final proof = await key.prove(InstalledAsk('a1', 'Eapp', 'AAAA', 'x'));
    expect(proof!.platform, 'android');
    expect(proof.evidence, [9, 9]);
    expect(calls.map((c) => c.method),
        ['publicPoint', 'signCall', 'attestNewKey', 'signStatement']);
    expect((calls[2].arguments as Map)['label'], 'k');
    expect(((calls[3].arguments as Map)['digest'] as Uint8List).length, 32,
        reason: 'the key signs the SHA-256 of the statement');
  });

  test('an answer that is not bytes is the hardware failing, said as such',
      () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (c) async => null);
    final hw = MethodChannelHardwareKey(
        channel: channel, platform: InstalledPlatform.tpm);
    expect(await hw.publicPoint('k'), isNull,
        reason: 'no key yet is not a failure');
    await expectLater(
        hw.signCall('k', Uint8List(1)), throwsA(isA<PlatformException>()));
    await expectLater(
        hw.attestNewKey('k', Uint8List(32)), throwsA(isA<PlatformException>()));
  });

  test(
      'on Apple the key comes from the attestation object and is kept, and a call is proved by the assertion',
      () async {
    // authData: rp hash, flags, counter, aaguid, id length, id, COSE key (x then y)
    final x = List<int>.filled(32, 5), y = List<int>.filled(32, 6);
    final cose = [
      0xa5,
      1,
      2,
      3,
      0x26,
      0x20,
      1,
      0x21,
      0x58,
      32,
      ...x,
      0x22,
      0x58,
      32,
      ...y
    ];
    final auth = [
      ...List<int>.filled(32, 1),
      0x45,
      0,
      0,
      0,
      0,
      ...List<int>.filled(16, 2),
      0,
      32,
      ...List<int>.filled(32, 3),
      ...cose
    ];
    final obj = Uint8List.fromList(
        [0xa1, 0x68, ...'authData'.codeUnits, 0x59, 0, auth.length, ...auth]);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (c) async {
      calls.add(c);
      return c.method == 'attestNewKey' ? obj : null;
    });
    final hw = MethodChannelHardwareKey(
        channel: channel, platform: InstalledPlatform.apple);
    expect(hw.callProofIsAssertion, isTrue);
    final made = await hw.attestNewKey('k', Uint8List(32));
    expect(made.point, [4, ...x, ...y]);
    expect(made.evidence, obj);
    final kept =
        calls.firstWhere((c) => c.method == 'keepPoint').arguments as Map;
    expect(kept['point'], [4, ...x, ...y],
        reason: 'the point is kept natively for the next run');
  });

  test('a TPM is enrolled, given the Identity Agent\'s credential, and then attests',
      () async {
    final chainCert = Uint8List.fromList([48, 1, 1]);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (c) async {
      calls.add(c);
      switch (c.method) {
        case 'tpmEnrol':
          return {
            'ek_public': Uint8List.fromList([0, 1, 1]),
            'ek_cert': Uint8List.fromList([48, 0]),
            'ek_chain': [chainCert],
            'ak_public': Uint8List.fromList([0, 1, 2]),
          };
        case 'tpmAttest':
          return {
            'point': point,
            'key_public': Uint8List.fromList([0, 1, 3]),
            'certify_info': Uint8List.fromList([1]),
            'certify_signature': Uint8List.fromList([2]),
            'credential_secret': Uint8List.fromList([3]),
          };
      }
      return null;
    });
    final hw = MethodChannelHardwareKey(
        channel: channel, platform: InstalledPlatform.tpm);
    TpmEnrolment? sent;
    final made = await hw.attestNewKey('k', Uint8List.fromList([7, 7]),
        exchange: (e) async {
      sent = e;
      return TpmCredential(Uint8List.fromList([0, 1, 9]), Uint8List.fromList([0, 1, 8]));
    });
    expect(calls.map((c) => c.method), ['tpmEnrol', 'tpmAttest'],
        reason: 'the credential is asked for between the two, never before the keys exist');
    expect(sent!.ekChain, [chainCert]);
    final attest = calls[1].arguments as Map;
    expect(attest['challenge'], [7, 7]);
    expect(attest['credential_blob'], [0, 1, 9]);
    expect(attest['secret'], [0, 1, 8]);
    expect(made.point, point);
    expect(String.fromCharCodes(made.evidence), contains('"credential_secret"'));
    // With nothing to ask for the credential the TPM is not asked at all.
    calls.clear();
    await expectLater(hw.attestNewKey('k', Uint8List(32)),
        throwsA(isA<PlatformException>()));
    expect(calls, isEmpty);
  });

  test('a grant is kept under the app, relay and back end together', () {
    expect(grantSlot('A', 'R', 'https://x'),
        isNot(grantSlot('A', 'R2', 'https://x')));
    expect(grantSlot('A', 'R', 'https://x'),
        isNot(grantSlot('A', 'R', 'https://y')));
  });
}
