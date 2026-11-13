import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/services/core_service.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

/// The core uses a list for an hour after its witnesses were asked. Fails when
/// an adoption does not hand the core the list first, or lets a failed fetch
/// stop the adoption.
void main() {
  Future<Uint8List?> bundle() async => Uint8List.fromList(utf8.encode('{"bundle_version":1}'));

  CoreService core(List<String> paths) => CoreService(
        baseUrl: 'http://127.0.0.1:5050',
        inner: MockClient((r) async {
          paths.add(r.url.path);
          return r.url.path == '/api/measurement-list'
              ? http.Response(jsonEncode({'sequence': 3}), 200)
              : http.Response(jsonEncode({'ok': true}), 200);
        }),
      );

  test('every adoption, however long after start, hands over the list before the POST', () async {
    final paths = <String>[];
    final c = core(paths);
    await c.adoptAgent(
        boxUrl: Uri.parse('https://box.example'), adoptionCode: 'x', measurementSources: [bundle]);
    // An hour and more later, the same app adopts again.
    await c.adoptAgent(
        boxUrl: Uri.parse('https://box.example'), adoptionCode: 'y', measurementSources: [bundle]);
    expect(paths, [
      '/api/measurement-list', '/api/pairing/adopt',
      '/api/measurement-list', '/api/pairing/adopt',
    ]);
  });

  test('a list that cannot be fetched does not stop the adoption being asked', () async {
    final paths = <String>[];
    await core(paths).adoptAgent(
        boxUrl: Uri.parse('https://box.example'),
        adoptionCode: 'x',
        measurementSources: [() async => throw Exception('offline')]);
    expect(paths, ['/api/pairing/adopt']);
  });
}
