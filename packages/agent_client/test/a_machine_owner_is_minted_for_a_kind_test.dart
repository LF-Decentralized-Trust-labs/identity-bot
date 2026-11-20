import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/services/core_service.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

/// The identity that will own a machine is minted for a kind of Identity
/// Agent, and the core keeps that kind from the moment it is minted, because
/// no key log carries it.
void main() {
  const origin = 'http://127.0.0.1:5050';

  (CoreService, List<http.Request>) coreRecording() {
    final asked = <http.Request>[];
    final core = CoreService(
      baseUrl: origin,
      ownerSeed: () async => Uint8List.fromList(List.filled(32, 7)),
      ownerAid: 'EOwner',
      inner: MockClient((req) async {
        asked.add(req);
        return http.Response(jsonEncode({'aid': 'EOWNERIDENTITY'}), 200);
      }),
    );
    return (core, asked);
  }

  test('the kind given is sent with the mint', () async {
    final (core, asked) = coreRecording();
    expect(await core.mintMachineOwner(kind: 'organisation'), 'EOWNERIDENTITY');
    expect(asked.single.url.toString(), '$origin/api/machines/owner-identity');
    expect(jsonDecode(asked.single.body), {'kind': 'organisation'});
  });

  test('with no kind given none is sent, so the core records no guess',
      () async {
    final (core, asked) = coreRecording();
    expect(await core.mintMachineOwner(), 'EOWNERIDENTITY');
    expect(jsonDecode(asked.single.body), <String, dynamic>{});
  });
}
