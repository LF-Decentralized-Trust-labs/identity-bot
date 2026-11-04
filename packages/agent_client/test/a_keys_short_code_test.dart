import 'dart:convert';

import 'package:agent_client/services/core_service.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

void main() {
  test('the short code is whatever the core answers, asked of the core', () async {
    final sent = <http.Request>[];
    final core = CoreService(
      baseUrl: 'http://127.0.0.1:5050',
      inner: MockClient((req) async {
        sent.add(req);
        return http.Response(jsonEncode({'short_code': 'M8PN-ME83-7RPK-D6FF'}), 200);
      }),
    );
    expect(await core.shortCodeOfAKey('DAtHgj5xCV3Vm-eKwnHFdu84n4e2RWGrB8-aTrzQLSBB'),
        'M8PN-ME83-7RPK-D6FF');
    expect(sent.single.url.path, '/api/machines/key-short-code');
    expect(jsonDecode(sent.single.body),
        {'public_key': 'DAtHgj5xCV3Vm-eKwnHFdu84n4e2RWGrB8-aTrzQLSBB'});
  });

  test('a refusal or an empty answer is an error, never a blank code', () async {
    for (final r in [http.Response('no', 400), http.Response('{}', 200)]) {
      final core = CoreService(
          baseUrl: 'http://127.0.0.1:5050', inner: MockClient((_) async => r));
      await expectLater(core.shortCodeOfAKey('Dk1'), throwsException);
    }
  });
}
