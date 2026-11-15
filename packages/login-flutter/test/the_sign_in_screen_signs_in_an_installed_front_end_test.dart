import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show PlatformException, SystemChannels;
import 'package:flutter_test/flutter_test.dart';
import 'package:login_dart/app_checks.dart' show AppLink;
import 'package:login_dart/app_session.dart';
import 'package:login_dart/front_end_key.dart';
import 'package:login_flutter/login_flutter.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../../login-dart/test/support/fake_app.dart';

// The screen an installed front end shows to sign in, against login_dart's fake utility app
// (sealed, relayed, signed answers): the button, the code to compare with the
// approving device's, the waiting state, and each refusal in words. Nothing here
// believes the app: AppSession does, and is tested in login-dart.

Future<void> open(WidgetTester t, FakeApp app, FakeHardware hw,
    {void Function(AppSession)? onSignedIn,
    String? pinned,
    String? notice,
    String appName = 'Task console',
    String? initialLink,
    void Function(String)? onLinkUsed,
    Future<FrontEndKey> Function(AppLink)? keyFor}) async {
  await t.binding.setSurfaceSize(const Size(900, 1600));
  addTearDown(() => t.binding.setSurfaceSize(null));
  await t.pumpWidget(MaterialApp(
      home: Scaffold(
          body: UtilityAppSignInScreen(
    appName: appName,
    pinnedLink: pinned,
    initialLink: initialLink,
    onLinkUsed: onLinkUsed,
    makeClient: () => app.client,
    keyFor: keyFor ?? (_) => HardwareFrontEndKey.open(hw, 'app-key'),
    storeFor: (_) => MemoryGrantStore(),
    every: const Duration(milliseconds: 10),
    deviceName: 'this Mac',
    notice: notice,
    onSignedIn: onSignedIn ?? (_) {},
  ))));
}

String linkOf(FakeApp app) {
  final k = appVectors['links'][0]['hash'] as String;
  final p = Uri.splitQueryString(k.substring(1));
  p['api'] = app.link.api;
  p['seal'] = app.link.seal;
  p['min'] = app.link.min;
  p['rid'] = app.link.rid;
  p['iat'] = '${DateTime.now().millisecondsSinceEpoch ~/ 1000}';
  return 'https://tasks.example/#${Uri(queryParameters: p).query}';
}

void main() {
  testWidgets(
      'says which device it is and what to check on the phone, then waits, then hands over the session',
      (t) async {
    final app = FakeApp(clock: DateTime.now().toUtc())..pendingAsks = 3;
    final hw = FakeHardware();
    AppSession? got;
    await open(t, app, hw, onSignedIn: (s) => got = s);
    await t.enterText(find.byKey(const Key('field-link')), linkOf(app));
    await t.tap(find.byKey(const Key('sign-in')));
    await t.pump(const Duration(milliseconds: 5));
    await t.pump(const Duration(milliseconds: 5));
    expect(find.textContaining('whether to let this Mac into Task console'),
        findsOneWidget);
    expect(find.byKey(const Key('fingerprint')), findsOneWidget);
    expect(find.byKey(const Key('waiting')), findsOneWidget);
    // The QR code is the main path; the raw link is behind a control, not on the screen.
    expect(find.byType(QrImageView), findsOneWidget);
    expect(find.byKey(const Key('pointer')), findsNothing);
    expect(find.text('https://ia.example/i/tok'), findsNothing);
    expect(find.text('Copy link instead'), findsOneWidget);
    expect(find.bySemanticsLabel('QR code to approve this sign-in in your Identity Agent'),
        findsOneWidget);
    expect(find.text('Sign in with Identity Agent'), findsNothing,
        reason: 'the button says it is connecting while a sign-in is under way');
    expect(got, isNull, reason: 'not signed in until the person approves');
    await t.pump(const Duration(milliseconds: 200));
    await t.pumpAndSettle(const Duration(milliseconds: 20));
    expect(got, isNotNull);
    expect(await got!.signedIn, isTrue);
    expect(app.startedWith!['frontEnd'], 'installed_app');
  });

  testWidgets(
      'a link that is not the app\'s is refused in words and nothing is sent',
      (t) async {
    final app = FakeApp();
    await open(t, app, FakeHardware());
    await t.enterText(
        find.byKey(const Key('field-link')), 'https://tasks.example/');
    await t.tap(find.byKey(const Key('sign-in')));
    await t.pump();
    expect(find.byKey(const Key('sign-in-error')), findsOneWidget);
    expect(app.calls, isEmpty);
  });

  testWidgets('a person who declined is told what to do, and no grant is kept',
      (t) async {
    final app = FakeApp(clock: DateTime.now().toUtc())..outcome = 'declined';
    AppSession? got;
    await open(t, app, FakeHardware(), onSignedIn: (s) => got = s);
    await t.enterText(find.byKey(const Key('field-link')), linkOf(app));
    await t.tap(find.byKey(const Key('sign-in')));
    await t.pumpAndSettle(const Duration(milliseconds: 20));
    expect(find.textContaining('not accepted'), findsOneWidget);
    expect(got, isNull);
  });

  testWidgets(
      'hardware that cannot prove its key is said so in its own words, not as the app being down',
      (t) async {
    final app = FakeApp(clock: DateTime.now().toUtc());
    await t.binding.setSurfaceSize(const Size(900, 1600));
    addTearDown(() => t.binding.setSurfaceSize(null));
    await t.pumpWidget(MaterialApp(
        home: Scaffold(
            body: UtilityAppSignInScreen(
      appName: 'Task console',
      makeClient: () => app.client,
      keyFor: (_) async => throw PlatformException(
          code: 'tpm_evidence_unavailable',
          message: 'The TPM cannot be proved yet.'),
      storeFor: (_) => MemoryGrantStore(),
      onSignedIn: (_) {},
    ))));
    await t.enterText(find.byKey(const Key('field-link')), linkOf(app));
    await t.tap(find.byKey(const Key('sign-in')));
    await t.pumpAndSettle();
    expect(find.textContaining('secure hardware could not make or prove'),
        findsOneWidget);
    expect(find.textContaining('The TPM cannot be proved yet.'), findsNothing,
        reason: 'what the platform code says is for the log');
    expect(find.textContaining('could not be reached'), findsNothing);
  });

  testWidgets('the button reads as the web\'s does, and says it is connecting while the key is proved',
      (t) async {
    final app = FakeApp(clock: DateTime.now().toUtc());
    final hold = Completer<FrontEndKey>();
    await open(t, app, FakeHardware(), keyFor: (_) => hold.future);
    expect(find.text('Sign in with Identity Agent'), findsOneWidget);
    await t.enterText(find.byKey(const Key('field-link')), linkOf(app));
    await t.tap(find.byKey(const Key('sign-in')));
    await t.pump();
    // Nothing is waiting on the person yet; something is, and it says what.
    expect(find.byKey(const Key('progress')), findsOneWidget);
    expect(find.text('Checking this device\'s secure hardware…'), findsOneWidget);
    expect(find.text('Connecting…'), findsOneWidget);
    expect(find.byKey(const Key('waiting')), findsNothing);
    hold.complete(await HardwareFrontEndKey.open(FakeHardware(), 'k'));
    await t.pumpAndSettle(const Duration(milliseconds: 20));
  });

  testWidgets('after a decline nothing says it is still waiting: no waiting text, code or fingerprint',
      (t) async {
    final app = FakeApp(clock: DateTime.now().toUtc())
      ..outcome = 'declined'
      ..pendingAsks = 2;
    await open(t, app, FakeHardware());
    await t.enterText(find.byKey(const Key('field-link')), linkOf(app));
    await t.tap(find.byKey(const Key('sign-in')));
    await t.pump(const Duration(milliseconds: 5));
    await t.pump(const Duration(milliseconds: 5));
    expect(find.byKey(const Key('waiting')), findsOneWidget, reason: 'it did wait');
    await t.pumpAndSettle(const Duration(milliseconds: 20));
    expect(find.textContaining('not accepted'), findsOneWidget);
    expect(find.byKey(const Key('waiting')), findsNothing);
    expect(find.byKey(const Key('fingerprint')), findsNothing);
    expect(find.byType(QrImageView), findsNothing);
    expect(find.byKey(const Key('progress')), findsNothing);
  });

  testWidgets('after a timeout nothing says it is still waiting either', (t) async {
    final app = FakeApp(clock: DateTime.now().toUtc())
      ..challengeLife = const Duration(seconds: 2)
      ..pendingAsks = 1 << 30;
    await open(t, app, FakeHardware());
    await t.enterText(find.byKey(const Key('field-link')), linkOf(app));
    await t.tap(find.byKey(const Key('sign-in')));
    for (var i = 0; i < 60 && find.byKey(const Key('sign-in-error')).evaluate().isEmpty; i++) {
      await t.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 100)));
      await t.pump(const Duration(milliseconds: 20));
    }
    expect(find.textContaining('ran out of time'), findsOneWidget);
    expect(find.byKey(const Key('waiting')), findsNothing);
    expect(find.byKey(const Key('fingerprint')), findsNothing);
    expect(find.byType(QrImageView), findsNothing);
  });

  testWidgets('a back end\'s refusal of a TPM key is shown as its sentence, and a bare failure says what to do, not an HTTP status',
      (t) async {
    const sentence =
        'This app\'s owner has not allowed sign-in from a Windows computer\'s security chip. Ask them to allow it, or sign in from a phone.';
    final app = FakeApp(clock: DateTime.now().toUtc())
      ..startStatus = 403
      ..startRefusal = sentence;
    await open(t, app, FakeHardware());
    await t.enterText(find.byKey(const Key('field-link')), linkOf(app));
    await t.tap(find.byKey(const Key('sign-in')));
    await t.pumpAndSettle(const Duration(milliseconds: 20));
    expect(find.text(sentence), findsOneWidget);
    expect(find.textContaining('HTTP'), findsNothing);

    final bare = FakeApp(clock: DateTime.now().toUtc())..startStatus = 500;
    await open(t, bare, FakeHardware());
    await t.enterText(find.byKey(const Key('field-link')), linkOf(bare));
    await t.tap(find.byKey(const Key('sign-in')));
    await t.pumpAndSettle(const Duration(milliseconds: 20));
    expect(find.textContaining('The app had a problem signing you in'), findsOneWidget);
    expect(find.textContaining('500'), findsNothing);
  });

  testWidgets('a device with no secure hardware is told so, not that the app could not be reached',
      (t) async {
    final app = FakeApp(clock: DateTime.now().toUtc());
    await open(t, app, FakeHardware(),
        keyFor: (_) async => throw UnsupportedError('no hardware'));
    await t.enterText(find.byKey(const Key('field-link')), linkOf(app));
    await t.tap(find.byKey(const Key('sign-in')));
    await t.pumpAndSettle();
    expect(find.text('This device has no secure hardware this app can sign in with.'),
        findsOneWidget);
    expect(find.textContaining('could not be reached'), findsNothing);
  });

  testWidgets('the app is called by its name, and as "this utility app" when it has none',
      (t) async {
    final app = FakeApp(clock: DateTime.now().toUtc());
    await open(t, app, FakeHardware(),
        appName: '  ', keyFor: (_) async => throw StateError('network'));
    await t.enterText(find.byKey(const Key('field-link')), linkOf(app));
    await t.tap(find.byKey(const Key('sign-in')));
    await t.pumpAndSettle();
    expect(find.textContaining('this utility app could not be reached'), findsOneWidget);
    expect(find.text('Sign in to this utility app'), findsOneWidget);
  });

  test('each platform error code is mapped to words a person can act on, never its developer text', () {
    for (final code in [
      'unsupported', 'no_key', 'no_enrolment', 'no_tpm', 'no_ek_certificate',
      'tpm_refused', 'tpm_response', 'hardware', 'no_answer', 'bad_args', 'something_new'
    ]) {
      final text = hardwareProblem(
          PlatformException(code: code, message: 'the device\'s TPM gave no ek_public (0x147)'),
          'Task console');
      expect(text, isNot(contains('ek_public')), reason: code);
      expect(text, isNot(contains('0x147')), reason: code);
      expect(text, endsWith('.'), reason: code);
    }
  });

  testWidgets('the raw link is copied on request', (t) async {
    final copied = <String?>[];
    t.binding.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
      if (call.method == 'Clipboard.setData') copied.add((call.arguments as Map)['text'] as String?);
      return null;
    });
    addTearDown(() => t.binding.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, null));
    final app = FakeApp(clock: DateTime.now().toUtc())..pendingAsks = 3;
    await open(t, app, FakeHardware());
    await t.enterText(find.byKey(const Key('field-link')), linkOf(app));
    await t.tap(find.byKey(const Key('sign-in')));
    await t.pump(const Duration(milliseconds: 5));
    await t.pump(const Duration(milliseconds: 5));
    await t.tap(find.byKey(const Key('copy-link')));
    await t.pump();
    expect(copied, ['https://ia.example/i/tok']);
    expect(find.text('Link copied'), findsOneWidget);
    await t.pumpAndSettle(const Duration(milliseconds: 20));
  });

  testWidgets('the link the person used last is offered again, and reported once a sign-in starts on it',
      (t) async {
    final app = FakeApp(clock: DateTime.now().toUtc())..pendingAsks = 2;
    final used = <String>[];
    await open(t, app, FakeHardware(), initialLink: linkOf(app), onLinkUsed: used.add);
    expect(find.widgetWithText(TextField, linkOf(app)), findsOneWidget);
    expect(used, isEmpty);
    await t.tap(find.byKey(const Key('sign-in')));
    await t.pumpAndSettle(const Duration(milliseconds: 20));
    expect(used, [linkOf(app)]);
  });

  testWidgets('a last link that is read after the screen is up fills the field, unless the person has typed one',
      (t) async {
    final app = FakeApp(clock: DateTime.now().toUtc());
    Widget screen(String? initial) => MaterialApp(
        home: Scaffold(
            body: UtilityAppSignInScreen(
                appName: 'Task console',
                initialLink: initial,
                makeClient: () => app.client,
                keyFor: (_) => HardwareFrontEndKey.open(FakeHardware(), 'k'),
                storeFor: (_) => MemoryGrantStore(),
                onSignedIn: (_) {})));
    await t.pumpWidget(screen(null));
    await t.pumpWidget(screen('https://a.example/#x'));
    expect(find.widgetWithText(TextField, 'https://a.example/#x'), findsOneWidget);
    await t.enterText(find.byKey(const Key('field-link')), 'https://typed.example/#y');
    await t.pumpWidget(screen('https://b.example/#z'));
    expect(find.widgetWithText(TextField, 'https://typed.example/#y'), findsOneWidget);
  });

  testWidgets('a link that is not the app\'s is not reported as used', (t) async {
    final app = FakeApp();
    final used = <String>[];
    await open(t, app, FakeHardware(), initialLink: 'https://tasks.example/', onLinkUsed: used.add);
    await t.tap(find.byKey(const Key('sign-in')));
    await t.pump();
    expect(used, isEmpty);
  });

  testWidgets('a notice about an ended session is shown above the sign-in',
      (t) async {
    await open(t, FakeApp(), FakeHardware(), notice: 'You are signed out.');
    expect(find.byKey(const Key('notice')), findsOneWidget);
  });
}
