import 'dart:convert';

import 'package:agent_client/services/core_service.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

/// The owner's two calls for choosing which contacts the watcher asks. Fails
/// when either goes to another route, drops the list, or reports a refusal as
/// success.
void main() {
  const agent = 'http://127.0.0.1:5050';

  test('reading the peers asks the owner route and reads the list', () async {
    late http.Request seen;
    final core = CoreService(
      baseUrl: agent,
      inner: MockClient((r) async {
        seen = r;
        return http.Response(jsonEncode({'aids': ['EOne'], 'enabled': true, 'max': 5}), 200);
      }),
    );
    final peers = await core.getWatcherPeers();
    expect(seen.method, 'GET');
    expect(seen.url.path, '/api/watcher/peers');
    expect(peers.aids, ['EOne']);
    expect(peers.max, 5);
  });

  test('choosing sends the list and a refusal is an error', () async {
    late http.Request seen;
    var status = 200;
    final core = CoreService(
      baseUrl: agent,
      inner: MockClient((r) async {
        seen = r;
        return http.Response(jsonEncode({'aids': ['ETwo'], 'enabled': true, 'max': 5}), status);
      }),
    );
    final peers = await core.setWatcherPeers(['ETwo']);
    expect(seen.method, 'PUT');
    expect(seen.url.path, '/api/watcher/peers');
    expect(jsonDecode(seen.body), {'aids': ['ETwo']});
    expect(peers.aids, ['ETwo']);

    status = 400;
    expect(() => core.setWatcherPeers(['EStranger']), throwsException);
  });
}
