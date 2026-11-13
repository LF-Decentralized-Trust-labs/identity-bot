import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/config/accepted_measurements.dart';
import 'package:agent_client/config/the_publishers_list_verdict.dart';
import 'package:agent_client/services/core_service.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

/// The app supplies a bundle and the core decides. Fails when the app sends it
/// anywhere but the core's route, decides anything itself, gives up on a source
/// the core said could still help, or goes on after an answer no other copy of
/// the bundle would change.
void main() {
  const agent = 'http://127.0.0.1:5050';

  CoreService coreAnswering(List<http.Response> answers, List<http.Request> seen) {
    var n = 0;
    return CoreService(
      baseUrl: agent,
      inner: MockClient((r) async {
        seen.add(r);
        return answers[n < answers.length ? n++ : answers.length - 1];
      }),
    );
  }

  http.Response ok(int seq) => http.Response(jsonEncode({'sequence': seq}), 200);
  http.Response no(int status, String title, [String details = '']) =>
      http.Response(jsonEncode({'error': title, 'details': details}), status);

  Future<Uint8List?> bundle(String s) async => Uint8List.fromList(utf8.encode(s));

  test('the bundle goes to the core as it is, and an accepted list says its sequence', () async {
    final seen = <http.Request>[];
    final core = coreAnswering([ok(7)], seen);
    final v = await refreshMeasurementList(core, sources: [() => bundle('{"bundle_version":1}')]);
    expect(v!.accepted, isTrue);
    expect(v.sequence, 7);
    expect(seen.single.method, 'POST');
    expect(seen.single.url.path, '/api/measurement-list');
    expect(seen.single.body, '{"bundle_version":1}');
  });

  test('a core that could not ask the witnesses, or a bundle that is behind, is tried from the next source', () async {
    final seen = <http.Request>[];
    final core = coreAnswering([
      no(503, 'The publisher\'s witnesses could not be asked just now'),
      no(409, 'The bundle is older than what the publisher\'s witnesses hold'),
      ok(8),
    ], seen);
    final v = await refreshMeasurementList(core, sources: [() => bundle('a'), () => bundle('b'), () => bundle('c')]);
    expect(v!.accepted, isTrue);
    expect(seen.map((r) => r.body), ['a', 'b', 'c']);
  });

  test('a refusal another copy would not change stops the search and is passed on in the core\'s words', () async {
    final seen = <http.Request>[];
    final core = coreAnswering([
      no(409, 'The publisher\'s history conflicts with the one this core holds', 'place 3'),
    ], seen);
    final v = await refreshMeasurementList(core, sources: [() => bundle('a'), () => bundle('b')]);
    expect(v!.kind, MeasurementListVerdictKind.conflict);
    expect(v.title, contains('conflicts'));
    expect(v.details, 'place 3');
    expect(seen, hasLength(1));
  });

  test('a build that trusts no publisher is its own verdict', () async {
    final core = coreAnswering([no(409, 'This build trusts no publisher of software lists')], []);
    final v = await refreshMeasurementList(core, sources: [() => bundle('a')]);
    expect(v!.kind, MeasurementListVerdictKind.noPublisher);
  });

  test('a source that fails, or gives nothing, is passed over and never throws', () async {
    final seen = <http.Request>[];
    final core = coreAnswering([ok(9)], seen);
    final v = await refreshMeasurementList(core, sources: [
      () async => throw Exception('no network'),
      () async => null,
      () => bundle('c'),
    ]);
    expect(v!.sequence, 9);
    expect(seen, hasLength(1));
    expect(await refreshMeasurementList(core, sources: [() async => null]), isNull);
  });
}
