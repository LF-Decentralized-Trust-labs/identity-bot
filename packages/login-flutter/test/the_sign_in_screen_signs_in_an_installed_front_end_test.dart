import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:login_dart/app_session.dart';
import 'package:login_dart/front_end_key.dart';
import 'package:login_flutter/login_flutter.dart';

import '../../login-dart/test/support/fake_app.dart';

// The screen an installed front end shows to sign in, against login_dart's fake utility app
// (sealed, relayed, signed answers): the button, the code to compare with the
// approving device's, the waiting state, and each refusal in words. Nothing here
// believes the app: AppSession does, and is tested in login-dart.

Future<void> open(WidgetTester t, FakeApp app, FakeHardware hw,
    {void Function(AppSession)? onSignedIn,
    String? pinned,
    String? notice}) async {
  await t.binding.setSurfaceSize(const Size(900, 1600));
  addTearDown(() => t.binding.setSurfaceSize(null));
  await t.pumpWidget(MaterialApp(
      home: Scaffold(
          body: UtilityAppSignInScreen(
    appName: 'Task console',
    pinnedLink: pinned,
    makeClient: () => app.client,
    assetId: (_) => app.assetId,
    keyFor: (_) => HardwareFrontEndKey.open(hw, 'app-key'),
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
    expect(find.byKey(const Key('pointer')), findsOneWidget);
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

  testWidgets('a notice about an ended session is shown above the sign-in',
      (t) async {
    await open(t, FakeApp(), FakeHardware(), notice: 'You are signed out.');
    expect(find.byKey(const Key('notice')), findsOneWidget);
  });
}
