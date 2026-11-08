import 'dart:convert';

import 'package:agent_client/services/recovery_service.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

// A cloud archive stays on the agent's disk and comes back as archive_ref, with
// archive_b64 empty. Verify and Start must send that reference; sending only
// archive_b64 (empty) is how a cloud restore through this client broke.
void main() {
  late List<Map<String, dynamic>> sent;
  late RecoveryService svc;

  setUp(() {
    sent = [];
    final client = MockClient((http.Request r) async {
      sent.add(jsonDecode(r.body) as Map<String, dynamic>);
      if (r.url.path.endsWith('/start')) {
        return http.Response(jsonEncode({'id': 's1'}), 201);
      }
      return http.Response(jsonEncode({'valid': true}), 200);
    });
    svc = RecoveryService(baseUrl: 'http://127.0.0.1:1', client: client);
  });

  test('a cloud retrieval result carries the reference', () {
    final r = RecoveryRetrieveResult.fromJson({
      'source': 'cloud',
      'archive_ref': 'restoring-fetch-123',
      'size_bytes': 9,
    });
    expect(r.archiveRef, 'restoring-fetch-123');
    expect(r.archiveB64, '');
  });

  test('verify sends the reference and no archive_b64', () async {
    await svc.verify(mnemonic: 'm', archiveRef: 'ref1', archiveName: 'k.iab');
    expect(sent.single['archive_ref'], 'ref1');
    expect(sent.single.containsKey('archive_b64'), isFalse);
    expect(sent.single['archive_name'], 'k.iab');
  });

  test('start sends the reference and no archive_b64', () async {
    await svc.start(mnemonic: 'm', archiveRef: 'ref1');
    expect(sent.single['archive_ref'], 'ref1');
    expect(sent.single.containsKey('archive_b64'), isFalse);
  });

  test('an archive given whole is still sent whole', () async {
    await svc.verify(mnemonic: 'm', archiveB64: 'QUJD');
    expect(sent.single['archive_b64'], 'QUJD');
    expect(sent.single.containsKey('archive_ref'), isFalse);
  });

  test('giving both or neither is refused before anything is sent', () async {
    await expectLater(
        svc.verify(mnemonic: 'm', archiveB64: 'QUJD', archiveRef: 'r'),
        throwsArgumentError);
    await expectLater(svc.start(mnemonic: 'm'), throwsArgumentError);
    expect(sent, isEmpty);
  });
}
