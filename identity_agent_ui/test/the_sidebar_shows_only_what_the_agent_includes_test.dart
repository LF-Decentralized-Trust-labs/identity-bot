import 'package:agent_client/services/agent_add_ons.dart';
import 'package:agent_client/services/core_service.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:identity_agent_ui/screens/desktop/desktop_sidebar.dart';

/// Apps and API Keys are the sandboxed-apps add-on's screens: an agent that
/// does not include it serves neither, so the sidebar does not offer them.
void main() {
  setUp(AgentAddOns.forgetAll);

  Future<void> agentIncludes(String url, List<String> addOns) =>
      AgentAddOns.at(url,
          ask: () async => CoreInfoResponse(
              name: '', description: '', version: '', phase: '',
              capabilities: const [], addOns: addOns));

  Future<void> showSidebar(WidgetTester tester, String url) async {
    // Tall enough that every item is built, not scrolled out of reach.
    tester.view.physicalSize = const Size(1400, 4000);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
    // The test font is wider than the app's, so the sidebar's header row
    // overflows here; that is not what this test is about.
    final shown = FlutterError.onError;
    FlutterError.onError = (details) {
      if (details.exceptionAsString().contains('overflowed')) return;
      shown?.call(details);
    };
    addTearDown(() => FlutterError.onError = shown);
    await tester.pumpWidget(MaterialApp(
      home: Scaffold(
        body: DesktopSidebar(
          // Settings open, so its items are listed.
          currentRoute: DesktopRoute.settingsAccount,
          onRouteSelected: (_) {},
          serverUrl: url,
        ),
      ),
    ));
    await tester.pump();
  }

  testWidgets('without sandboxed apps, there is no Apps and no API Keys', (tester) async {
    await agentIncludes('http://core-only', []);
    await showSidebar(tester, 'http://core-only');
    expect(find.text('Apps'), findsNothing);
    expect(find.text('API Keys'), findsNothing);
    expect(find.text('Contacts'), findsOneWidget);
  });

  testWidgets('with sandboxed apps, Apps and API Keys are there', (tester) async {
    await agentIncludes('http://with-apps', ['sandboxed_apps']);
    await showSidebar(tester, 'http://with-apps');
    expect(find.text('Apps'), findsOneWidget);
    expect(find.text('API Keys'), findsOneWidget);
  });
}
