import 'dart:convert';
import 'dart:typed_data';

import 'package:login_dart/app_checks.dart';
import 'package:login_dart/app_session.dart';
import 'package:login_dart/front_end_key.dart';
import 'package:login_dart/installed_app.dart';
import 'package:test/test.dart';

import 'support/fake_app.dart';

// An installed front end's whole life with its app's back end, through the SDK
// alone and over the sealed, relayed route (ADR-072 section 2): it proves its
// hardware key for an ask, signs in as `installed_app`, is bound to an app-key
// grant, and makes signed calls the app answers; it is refused where the app is
// not the app, and an ended grant says so.

AppSession open(FakeApp app, FrontEndKey key, {GrantStore? store}) =>
    AppSession(app.client, app.link, key, store: store, now: () => app.clock);

void main() {
  test('an installed front end proves its key, signs in and holds a grant',
      () async {
    final app = FakeApp();
    final hw = FakeHardware();
    final key = await HardwareFrontEndKey.open(hw, 'app-key');
    expect(key.kind, FrontEndKind.installedApp);
    expect(key.isNonExtractable, isTrue);
    final s = open(app, key);
    final before = key.thumbprint;
    final started = await s.start();
    expect(key.thumbprint, isNot(before),
        reason:
            'a hardware key is made for the ask, so the sign-in names the new key');
    expect(hw.made, 1);
    expect(started.pointer, 'https://ia.example/i/tok');
    expect(started.fingerprint, keyFingerprint(key.thumbprint));
    final sent = app.startedWith!;
    expect(sent['frontEnd'], 'installed_app');
    expect(sent['browserKey'], key.thumbprint);
    final proof = sent['proof'] as Map<String, dynamic>;
    expect(proof['platform'], 'android');
    expect(proof['ask'], app.asked);
    expect(base64.decode(proof['evidence'] as String), isNotEmpty);
    // the hardware was asked to attest the challenge the back end gave, and the key signed
    // the statement the Identity Agent builds for it, whose digest is the shared one
    expect(hw.lastChallenge, List<int>.generate(32, (i) => 100 + i));
    expect(
        hw.lastDigest,
        installedAppStatementDigest(
            app.assetId, hw.lastChallenge!, key.thumbprint));
    await s.wait(started, every: Duration.zero);
    expect(await s.signedIn, isTrue);
  });

  test(
      'every call after sign-in is sealed, carries the grant and a proof the key made, and is answered',
      () async {
    final app = FakeApp();
    final key = await HardwareFrontEndKey.open(FakeHardware(), 'k');
    final store = MemoryGrantStore();
    final s = open(app, key, store: store);
    await store.write('grant-1');
    final r = await s.call('POST', '/session/api/thing', '{"a":1}');
    expect(r.json()['ok'], isTrue);
    expect(app.calls.map((c) => c.target),
        ['/session/whoami', '/session/api/thing'],
        reason: 'the app\'s clock is asked for first');
    final c = app.calls.last;
    expect(c.headers['authorization'], 'Bearer grant-1');
    final ts = c.headers['x-browser-proof-time'] as String;
    final nonce = c.headers['x-browser-proof-nonce'] as String;
    expect(
        key.verify(
            backEndProofString('POST', '/session/api/thing', ts, nonce,
                sessionBinding('grant-1'), utf8.encode('{"a":1}')),
            c.headers['x-browser-proof'] as String),
        isTrue,
        reason: 'the proof is the hardware key\'s, over this call');
  });

  test('a call with no grant is a sign-in to make, and goes nowhere', () async {
    final app = FakeApp();
    final s = open(app, await HardwareFrontEndKey.open(FakeHardware(), 'k'));
    await expectLater(
        s.call('GET', '/session/x'), throwsA(isA<SessionEnded>()));
    expect(app.calls, isEmpty);
  });

  test(
      'a 401 forgets the grant and says to sign in again; signing out tells the app',
      () async {
    final app = FakeApp();
    final store = MemoryGrantStore();
    final s = open(app, await HardwareFrontEndKey.open(FakeHardware(), 'k'),
        store: store);
    await store.write('grant-1');
    app.status401After = 1; // whoami, then ended
    await expectLater(
        s.call('GET', '/session/x'),
        throwsA(isA<SessionEnded>()
            .having((e) => e.message, 'message', contains('Sign in again'))));
    expect(await store.read(), isNull);
    await store.write('grant-2');
    app.status401After = -1;
    await s.signOut();
    expect(app.calls.last.target, '/session/signout');
    expect(await store.read(), isNull);
  });

  test(
      'a device with no hardware proof cannot sign in as an installed front end',
      () async {
    final app = FakeApp();
    final s = open(app, SoftwareFrontEndKey.generate());
    // a software key is a browser's kind: it starts as a browser and never carries a proof
    await s.start();
    expect(app.startedWith!['frontEnd'], 'browser');
    expect(app.startedWith!.containsKey('proof'), isFalse);
  });

  test('a declined sign-in is said in words and keeps no grant', () async {
    final app = FakeApp()..outcome = 'declined';
    final s = open(app, await HardwareFrontEndKey.open(FakeHardware(), 'k'));
    final started = await s.start();
    await expectLater(
        s.wait(started, every: Duration.zero),
        throwsA(isA<SignInFailed>()
            .having((e) => e.message, 'message', contains('not accepted'))));
    expect(await s.signedIn, isFalse);
  });

  test('a challenge for another key is refused, not shown', () async {
    final app = FakeApp()
      ..challengeKey = 'not-the-key-the-app-signed-for-00000000000';
    final s = open(app, await HardwareFrontEndKey.open(FakeHardware(), 'a'));
    await expectLater(
        s.start(),
        throwsA(isA<SignInFailed>()
            .having((e) => e.message, 'message', contains('own key'))));
  });

  test('the key is read only as an uncompressed P-256 point', () async {
    final bad = _BadHardware();
    await expectLater(
        HardwareFrontEndKey.open(bad, 'k'), throwsA(isA<TrustRefused>()));
  });

  test('a DER signature from hardware is the raw one a proof carries', () {
    final k = SoftwareFrontEndKey.generate();
    return k.sign('x').then((raw) {
      expect(derToRaw(rawToDer(b64uDecode(raw)!)), b64uDecode(raw));
      expect(
          () => derToRaw(Uint8List.fromList([1, 2, 3])), throwsFormatException);
    });
  });
}

class _BadHardware extends FakeHardware {
  @override
  Future<Uint8List> publicPoint(String label) async => Uint8List(64);
}
