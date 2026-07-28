import 'package:flutter_test/flutter_test.dart';
import 'package:identity_agent_ui/services/root_seed_handoff.dart';

void main() {
  test('a local core is recognised', () {
    for (final url in [
      'http://localhost:5050',
      'http://127.0.0.1:5050',
      'http://[::1]:5050',
    ]) {
      expect(RootSeedHandoff.isLocalCore(url), isTrue, reason: url);
    }
  });

  // The whole point: the root seed derives every key this identity will ever
  // have. Sending it to a machine somebody else operates cannot be undone.
  test('anything not plainly local is treated as remote', () {
    for (final url in [
      'https://abc-123.agent.grapeid.org',
      'http://192.168.0.81:5050',
      'https://localhost.example.com',
      'http://127.0.0.1.evil.com',
      'not a url at all',
      '',
    ]) {
      expect(RootSeedHandoff.isLocalCore(url), isFalse, reason: url);
    }
  });
}
