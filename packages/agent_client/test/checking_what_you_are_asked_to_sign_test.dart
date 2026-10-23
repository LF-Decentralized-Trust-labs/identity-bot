import 'dart:convert';

import 'package:agent_client/services/checking_what_you_are_asked_to_sign.dart';
import 'package:http/http.dart' as http;
import 'package:test/test.dart';

const _own = 'http://127.0.0.1:8642';

class _Recorder extends http.BaseClient {
  final List<http.Request> sent = [];
  String body = '';
  int status = 200;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    sent.add(request as http.Request);
    return http.StreamedResponse(Stream.value(utf8.encode(body)), status);
  }
}

void main() {
  const asked = AskedToSign(
    id: 'r1',
    kind: 'grant-issuance',
    payloadB64: 'aXhu',
    credentialB64: 'YWNkYw==',
    issuanceB64: 'aXNz',
  );

  test(
      'it asks this device\'s own core, with every part, and shows only what '
      'the credential says', () async {
    final rec = _Recorder()
      ..body = jsonEncode({
        'kind': 'machine',
        'issuer': 'EOrg',
        'sn': 7,
        'prior': 'EPrior',
        'holder': 'BLaptop',
        'name': 'the laptop',
        'public_key': 'DKey',
        'key_fingerprint': 'ABCD-EFGH',
        'grade': 'enrolled',
      });
    final shown =
        await CheckingWhatYouAreAskedToSign(ownOrigin: _own, client: rec)
            .check(asked);
    expect(rec.sent.single.url.toString(), '$_own/api/signing-requests/check');
    final sent = jsonDecode(rec.sent.single.body) as Map<String, dynamic>;
    expect(sent['payload_b64'], 'aXhu');
    expect(sent['credential_b64'], 'YWNkYw==');
    expect(sent['issuance_b64'], 'aXNz');
    expect(shown.kind, 'machine');
    expect(shown.holder, 'BLaptop');
    expect(shown.keyFingerprint, 'ABCD-EFGH');
  });

  test('a grant the core will not vouch for is never returned to be signed',
      () async {
    final rec = _Recorder()
      ..status = 422
      ..body = '{"error":"this is not safe to sign"}';
    await expectLater(
      CheckingWhatYouAreAskedToSign(ownOrigin: _own, client: rec).check(asked),
      throwsA(isA<NotSafeToSign>()),
    );
  });

  test('the queue entry is read with its parts', () {
    final r = AskedToSign.fromJson({
      'id': 'r2',
      'kind': 'registry-inception',
      'payload_b64': 'aXhu',
      'registry_b64': 'dmNw',
    });
    expect(r.isAGrant, isTrue);
    expect(r.registryB64, 'dmNw');
    expect(r.credentialB64, isNull);
  });
}
