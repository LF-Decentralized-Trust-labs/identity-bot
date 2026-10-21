import 'dart:convert';

import 'package:agent_client/services/core_service.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

/// The settings screen's calls reach the routes the core serves, with the
/// fields it reads, and a refusal comes back in the relay's own words.
void main() {
  late List<http.Request> sent;
  late CoreService core;

  setUp(() {
    sent = [];
    core = CoreService(
      baseUrl: 'http://127.0.0.1:5050',
      inner: MockClient((req) async {
        sent.add(req);
        if (req.url.path.endsWith('/domains/verify')) {
          return http.Response(
              jsonEncode({'error': 'The domain is not proved yet', 'details': 'the TXT record is not there yet'}),
              409);
        }
        if (req.url.path.endsWith('/domains') && req.method == 'GET') {
          return http.Response(
              jsonEncode({
                'domains': [
                  {'domain': 'id.example.org', 'state': 'waiting_for_dns'}
                ]
              }),
              200);
        }
        return http.Response(jsonEncode({'state': 'active', 'relay': {'state': 'active'}}), 200);
      }),
    );
  });

  test('saving reachability sends only what changed, to the route that applies it', () async {
    final out = await core.saveReachability(mode: 'public', publicRelayName: 'acme');
    expect(sent.single.method, 'PUT');
    expect(sent.single.url.path, '/api/settings/reachability');
    expect(jsonDecode(sent.single.body), {'mode': 'public', 'public_relay_name': 'acme'});
    expect(out['relay']['state'], 'active');
  });

  test('each call reaches its route', () async {
    await core.getRelayStatus();
    await core.releasePublicName();
    await core.requestCustomDomain('id.example.org');
    final domains = await core.listCustomDomains();
    expect(sent.map((r) => '${r.method} ${r.url.path}'), [
      'GET /api/settings/reachability/relay',
      'POST /api/settings/reachability/name/release',
      'POST /api/settings/reachability/domains',
      'GET /api/settings/reachability/domains',
    ]);
    expect(jsonDecode(sent[2].body), {'domain': 'id.example.org'});
    expect(domains.single['state'], 'waiting_for_dns');
  });

  test('a refusal says why, in the words the core gave', () async {
    expect(
      () => core.verifyCustomDomain('id.example.org'),
      throwsA(predicate((e) => '$e'.contains('the TXT record is not there yet'))),
    );
  });
}
