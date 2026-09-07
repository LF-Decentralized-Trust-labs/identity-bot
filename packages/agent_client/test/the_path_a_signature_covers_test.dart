import 'package:agent_client/services/the_path_a_signature_covers.dart';
import 'package:test/test.dart';

/// A signed request must be signed over the path the agent VERIFIES, which is
/// the path it receives — and a path-mounting relay strips its token before the
/// agent sees it. These pin that the signed path is the agent's own, so a write
/// to a relayed box stops being refused for a signature over a path the agent
/// never rebuilds.
void main() {
  test('a relay mount prefix is stripped, leaving what the agent sees', () {
    // The box lives under a path token on a shared host; the relay removes the
    // token, so the box routes and verifies on /api/controllers.
    expect(
      pathSignatureCovers(
        'https://agent.example/cl6uodq_E0n8a8sTPnIAQQ',
        Uri.parse(
            'https://agent.example/cl6uodq_E0n8a8sTPnIAQQ/api/controllers'),
      ),
      '/api/controllers',
    );
  });

  test('a bare origin is left untouched — nothing to strip', () {
    // A self-hosted box reached directly: the path is already what it verifies.
    expect(
      pathSignatureCovers('https://box.example',
          Uri.parse('https://box.example/api/controllers')),
      '/api/controllers',
    );
  });

  test('a trailing slash on the origin does not leave a doubled separator', () {
    expect(
      pathSignatureCovers('https://agent.example/cl6uodq_E0n8a8sTPnIAQQ/',
          Uri.parse('https://agent.example/cl6uodq_E0n8a8sTPnIAQQ/api/kel')),
      '/api/kel',
    );
  });

  test('the prefix reached with no further path becomes root', () {
    expect(
      pathSignatureCovers('https://agent.example/cl6uodq_E0n8a8sTPnIAQQ',
          Uri.parse('https://agent.example/cl6uodq_E0n8a8sTPnIAQQ')),
      '/',
    );
  });

  test('a path that is not under the prefix is signed as-is, failing closed',
      () {
    // A near-miss that only shares a leading string must NOT be mis-stripped: it
    // is signed unchanged, and the agent refuses it rather than accepting a path
    // the caller did not send.
    expect(
      pathSignatureCovers('https://agent.example/cl6uodq_E0n8a8sTPnIAQQ',
          Uri.parse('https://agent.example/cl6uodq_E0n8a8sTPnIAQQ-other/x')),
      '/cl6uodq_E0n8a8sTPnIAQQ-other/x',
    );
  });
}
