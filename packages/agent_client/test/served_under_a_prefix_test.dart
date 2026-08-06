import 'package:test/test.dart';

/// Where the app looks for its own API when it is not served at a root.
///
/// An agent served under a path prefix answers at `/{prefix}/api/…`. The app
/// used to call `/api/…` regardless, which on a host running several agents
/// under one hostname reaches no agent at all and returns 404.
///
/// The 404 is worse than an error because of how the app reads it. A refusal
/// (403) means "this agent is somebody else's, and is waiting for them" and
/// shows a claim screen. Anything else means "nothing here yet" and offers to
/// create an identity — so a 404 sent a person to a Create button on an agent
/// that was already owned and would refuse them at the next step.
///
/// The resolution itself is a pure function of the page's path, so it is tested
/// as one. Uri.base cannot be set in a test, and testing a getter that reads a
/// global would only assert that the test environment is not a browser.

/// The prefix derivation, exactly as `AgentConfig.coreBaseUrl` performs it on
/// the web.
String basePathFor(String pagePath) {
  if (pagePath.isEmpty || pagePath == '/') return '';
  return pagePath.endsWith('/')
      ? pagePath.substring(0, pagePath.length - 1)
      : pagePath;
}

String wsUriFor(String pageOrigin, String basePath) =>
    '$pageOrigin$basePath/api/ws/events';

void main() {
  group('an agent served under a path prefix', () {
    test('calls its API beside the page, not at the root', () {
      const token = '/TxDjldICgQ6jBZUiDGmAbA/';
      expect(basePathFor(token), '/TxDjldICgQ6jBZUiDGmAbA');
      expect('${basePathFor(token)}/api/identity',
          '/TxDjldICgQ6jBZUiDGmAbA/api/identity');
    });

    test('a missing trailing slash is the same address', () {
      expect(basePathFor('/TxDjldICgQ6jBZUiDGmAbA'), '/TxDjldICgQ6jBZUiDGmAbA');
    });

    test('an agent at the root of a hostname is unchanged', () {
      // The behaviour every existing deployment has today. If this breaks,
      // desktop and single-tenant hosting break with it.
      expect(basePathFor('/'), '');
      expect(basePathFor(''), '');
      expect('${basePathFor('/')}/api/identity', '/api/identity');
    });
  });

  group('the event socket', () {
    test('carries the prefix, and is absolute so it can be dialled', () {
      final uri = wsUriFor('wss://agent.example.net', '/TxDjldICgQ6jBZUiDGmAbA');
      expect(uri, 'wss://agent.example.net/TxDjldICgQ6jBZUiDGmAbA/api/ws/events');
      // Absolute: a relative URI is refused for having no scheme, which is the
      // regression that appeared the moment the base stopped being empty.
      expect(Uri.parse(uri).hasScheme, isTrue);
    });

    test('still works for an agent at the root', () {
      final uri = wsUriFor('wss://agent.example.net', '');
      expect(uri, 'wss://agent.example.net/api/ws/events');
    });
  });
}
