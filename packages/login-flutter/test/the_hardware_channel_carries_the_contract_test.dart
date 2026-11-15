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
        case 'sign':
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
    final proof = await key.prove('Eapp', InstalledAsk('a1', 'AAAA', 'x'));
    expect(proof!.platform, 'android');
    expect(proof.evidence, [9, 9]);
    expect(calls.map((c) => c.method),
        ['publicPoint', 'sign', 'attestNewKey', 'signStatement']);
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
    await expectLater(hw.publicPoint('k'), throwsA(isA<PlatformException>()));
    await expectLater(
        hw.attestNewKey('k', Uint8List(32)), throwsA(isA<PlatformException>()));
  });

  test('a grant is kept under the app, relay and back end together', () {
    expect(grantSlot('A', 'R', 'https://x'),
        isNot(grantSlot('A', 'R2', 'https://x')));
    expect(grantSlot('A', 'R', 'https://x'),
        isNot(grantSlot('A', 'R', 'https://y')));
  });
}
