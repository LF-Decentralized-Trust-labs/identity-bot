import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:login_dart/app_checks.dart';
import 'package:login_dart/app_session.dart';
import 'package:login_dart/front_end_key.dart';
import 'package:login_dart/installed_app.dart';
import 'package:test/test.dart';

import 'support/fake_app.dart';

// Whether an installed front end must sign in with a hardware key is its app
// owner's word, and the Identity Agent's to hold (ADR-072 Amendment 17). The ask
// says which platforms the owner accepts; the front end uses the hardware's key
// where its hardware is one of them, and otherwise a key in software where the
// owner allows that. These tests hold the front end's side: it never sends a key in
// software to an app whose owner said hardware only, and what it sends is what the
// Identity Agent checks.

/// A fake app whose asks say [accepts].
class _Accepting extends FakeApp {
  final List<String>? accepts;
  _Accepting(this.accepts);
  @override
  ({int status, Map<String, dynamic> body}) route(
      String method, String target, Map<String, dynamic> headers, String body) {
    final r = super.route(method, target, headers, body);
    if ('$method $target' == 'POST /signin/installed-key/ask' && accepts != null) {
      return (status: r.status, body: {...r.body, 'accepts': accepts});
    }
    return r;
  }
}

/// Hardware that cannot make a key, as a computer with its TPM switched off.
class _BrokenHardware extends FakeHardware {
  @override
  Future<({Uint8List point, Uint8List evidence})> attestNewKey(
          String label, Uint8List challenge,
          {CredentialExchange? exchange}) async =>
      throw StateError('no_tpm');
}

/// A TPM that asks the app's back end for its credential, as a Windows front end does.
class _Tpm extends FakeHardware {
  @override
  String get platform => InstalledPlatform.tpm;
  @override
  Future<({Uint8List point, Uint8List evidence})> attestNewKey(
      String label, Uint8List challenge,
      {CredentialExchange? exchange}) async {
    await exchange!(TpmEnrolment(
        ekPublic: Uint8List(1), ekCert: Uint8List(1), akPublic: Uint8List(1)));
    return super.attestNewKey(label, challenge);
  }
}

Future<(InstalledFrontEndKey, AppSession)> _open(FakeApp app,
    {HardwareKeyPlatform? hardware, KeyStore? store}) async {
  final key = await InstalledFrontEndKey.open(
      hardware: hardware, label: 'app-key', keyStore: store ?? MemoryKeyStore());
  return (key, AppSession(app.client, app.link, key, now: () => app.clock));
}

void main() {
  test('where the owner accepts the device\'s hardware, the hardware makes the key',
      () async {
    final app = _Accepting(['android', 'software']);
    final (key, s) = await _open(app, hardware: FakeHardware());
    await s.start();
    expect((app.startedWith!['proof'] as Map)['platform'], 'android');
    expect(key.grade, KeyGrade.hardware);
    expect(key.isNonExtractable, isTrue);
  });

  test('where the owner does not accept it but allows software, a key in software signs in',
      () async {
    final app = _Accepting(['apple', 'software']);
    final store = MemoryKeyStore();
    final (key, s) = await _open(app, hardware: FakeHardware(), store: store);
    final started = await s.start();
    final sent = app.startedWith!;
    final proof = sent['proof'] as Map<String, dynamic>;
    expect(sent['frontEnd'], 'installed_app');
    expect(proof['platform'], 'software');
    expect(key.grade, KeyGrade.software);
    expect(key.isNonExtractable, isFalse);
    // Its evidence is its own point, and it signed the statement the Identity Agent builds.
    expect(base64.decode(proof['evidence'] as String),
        [4, ...b64uDecode(key.x)!, ...b64uDecode(key.y)!]);
    final challenge = List<int>.generate(32, (i) => 100 + i);
    final raw = derToRaw(base64.decode(proof['key_signature'] as String));
    expect(
        key.verify(installedAppStatement(app.assetId, challenge, key.thumbprint),
            b64uEncode(raw)),
        isTrue);
    await s.wait(started, every: Duration.zero);
    expect(await s.signedIn, isTrue);
    // After a restart it is the same key, and it still signs.
    final again = await InstalledFrontEndKey.open(
        hardware: FakeHardware(), label: 'app-key', keyStore: store);
    expect(again.thumbprint, key.thumbprint);
    expect(again.grade, KeyGrade.software);
    expect(again.verify('call', await again.sign('call')), isTrue);
  });

  test('the app\'s name for its device goes with a hardware key\'s proof, never a software one',
      () async {
    // ADR-072 Amendment 14 names the device a hardware key was proved on; a key in
    // software proves no device, so its proof carries no name either.
    final hw = _Accepting(['android', 'software']);
    final hwKey = await InstalledFrontEndKey.open(
        hardware: FakeHardware(),
        label: 'app-key',
        keyStore: MemoryKeyStore(),
        deviceName: 'Ann\'s Pixel');
    await AppSession(hw.client, hw.link, hwKey, now: () => hw.clock).start();
    expect((hw.startedWith!['proof'] as Map)['device_name'], 'Ann\'s Pixel');
    final sw = _Accepting(['apple', 'software']);
    final swKey = await InstalledFrontEndKey.open(
        hardware: FakeHardware(),
        label: 'app-key',
        keyStore: MemoryKeyStore(),
        deviceName: 'Ann\'s Pixel');
    await AppSession(sw.client, sw.link, swKey, now: () => sw.clock).start();
    final proof = sw.startedWith!['proof'] as Map;
    expect(proof['platform'], 'software');
    expect(proof.containsKey('device_name'), isFalse);
  });

  test('where the owner requires hardware the device\'s hardware is not, nothing is sent',
      () async {
    for (final hardware in [null, FakeHardware()]) {
      final app = _Accepting(['tpm']);
      final (_, s) = await _open(app, hardware: hardware);
      await expectLater(
          s.start(),
          throwsA(isA<SignInFailed>().having(
              (e) => e.message, 'message', contains('requires a sign-in key kept in a device\'s secure hardware'))));
      expect(app.startedWith, isNull,
          reason: 'a key in software is never offered to an app whose owner requires hardware');
    }
  });

  test('a device whose hardware fails falls back to software only where the owner allows it',
      () async {
    final allowed = _Accepting(['android', 'software']);
    final (key, s) = await _open(allowed, hardware: _BrokenHardware());
    await s.start();
    expect((allowed.startedWith!['proof'] as Map)['platform'], 'software');
    expect(key.grade, KeyGrade.software);

    final required = _Accepting(['android']);
    final (_, s2) = await _open(required, hardware: _BrokenHardware());
    await expectLater(s2.start(), throwsA(isA<StateError>()));
    expect(required.startedWith, isNull);
  });

  test('a refusal from the app\'s back end is passed on, never turned into a key in software',
      () async {
    final app = _Accepting(['tpm', 'software'])..refuseCredential = true;
    final (key, s) = await _open(app, hardware: _Tpm());
    await expectLater(s.start(), throwsA(isA<SignInFailed>()));
    expect(app.startedWith, isNull);
    expect(key.grade, isNull);
  });

  test('a back end that does not say leaves the Identity Agent to decide', () async {
    final noHardware = _Accepting(null);
    final (k1, s1) = await _open(noHardware);
    await s1.start();
    expect((noHardware.startedWith!['proof'] as Map)['platform'], 'software');
    expect(k1.grade, KeyGrade.software);

    final withHardware = _Accepting(null);
    final (k2, s2) = await _open(withHardware, hardware: FakeHardware());
    await s2.start();
    expect((withHardware.startedWith!['proof'] as Map)['platform'], 'android');
    expect(k2.grade, KeyGrade.hardware);
  });

  test('an ask whose accepts is not a list of names is refused', () {
    expect(
        () => InstalledAsk.fromJson({
              'ask': 'a',
              'asset_id': 'x',
              'challenge': b64uEncode([1, 2, 3]),
              'expires': 'e',
              'accepts': 'software'
            }),
        throwsA(isA<TrustRefused>()));
    expect(
        InstalledAsk.fromJson({
          'ask': 'a',
          'asset_id': 'x',
          'challenge': b64uEncode([1, 2, 3]),
          'expires': 'e',
          'accepts': ['software']
        }).accepts,
        ['software']);
  });

  test('a key in software signs the statement exactly as the shared vector says, which Go checks',
      () async {
    final v = (jsonDecode(File('../login-web/test-vectors/installed-app.json')
            .readAsStringSync()) as Map<String, dynamic>)['software_proof']
        as Map<String, dynamic>;
    final hex = v['scalar_hex'] as String;
    final d = [
      for (var i = 0; i < hex.length; i += 2)
        int.parse(hex.substring(i, i + 2), radix: 16)
    ];
    final k = SoftwareFrontEndKey.fromScalar(d);
    expect(k.x, v['x']);
    expect(k.y, v['y']);
    expect(k.thumbprint, v['thumbprint']);
    final raw = b64uDecode(await k.sign(installedAppStatement(
        v['asset_id'] as String,
        b64uDecode(v['challenge_b64u'] as String)!,
        k.thumbprint)))!;
    expect(base64.encode(rawToDer(raw)), v['key_signature']);
    expect(base64.encode([4, ...b64uDecode(k.x)!, ...b64uDecode(k.y)!]),
        v['evidence']);
  });
}
