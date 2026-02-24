import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:identity_agent_ui/main.dart';

void main() {
  testWidgets('App loads smoke test', (WidgetTester tester) async {
    await tester.pumpWidget(const IdentityAgentApp());
    await tester.pump();
    expect(find.byType(MaterialApp), findsOneWidget);
  });
}
