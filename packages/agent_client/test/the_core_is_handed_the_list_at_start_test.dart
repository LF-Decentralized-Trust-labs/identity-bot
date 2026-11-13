import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/services/core_service.dart';
import 'package:agent_client/services/identity_profiles.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

/// A core keeps no list across a restart, and after one accepted list it
/// refuses every box until it is handed one again. Fails when starting the
/// active identity no longer sends the core the publisher's bundle.
void main() {
  Future<Uint8List?> bundle() async => Uint8List.fromList(utf8.encode('{"bundle_version":1}'));

  test('the start-up handover posts the bundle to the core route', () async {
    final seen = <http.Request>[];
    final core = CoreService(
      baseUrl: 'http://127.0.0.1:5050',
      inner: MockClient((r) async {
        seen.add(r);
        return http.Response(jsonEncode({'sequence': 3}), 200);
      }),
    );
    final v = await IdentityProfiles.handTheCoreTheMeasurementList(core, sources: [bundle]);
    expect(v!.accepted, isTrue);
    expect(seen.single.url.path, '/api/measurement-list');
  });

  test('a core that cannot be reached does not stop the start', () async {
    final core = CoreService(
      baseUrl: 'http://127.0.0.1:5050',
      inner: MockClient((r) async => throw http.ClientException('refused')),
    );
    expect(await IdentityProfiles.handTheCoreTheMeasurementList(core, sources: [bundle]), isNull);
  });
}
