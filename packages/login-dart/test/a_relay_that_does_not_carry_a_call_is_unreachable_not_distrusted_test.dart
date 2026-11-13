import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:login_dart/app_checks.dart';
import 'package:login_dart/seal.dart';
import 'package:test/test.dart';

// A relay that fails to carry a call (a restart, a busy moment) has not given a
// wrong answer: the person is told to try again, and is not told to distrust the
// connection. An answer that does not open is the opposite, and is distrusted.

final v =
    jsonDecode(File('../login-web/test-vectors/seal.json').readAsStringSync())
        as Map<String, dynamic>;

void main() {
  final rid = v['rid'] as String;
  final spk = b64uDecode((v['seal_key'] as Map)['public_b64u'] as String)!;
  final link = AppLink('Eapp', 'k', rid, 'https://tasks.example', 's', '0.x');

  Future<Object?> callThrough(http.Client c) async {
    try {
      await sealedCall(c, link, spk,
          method: 'GET',
          target: '/session/whoami',
          headers: {},
          body: const [],
          nonce: 'abcdefghijkl',
          logs: AnswerLogs(),
          now: DateTime.utc(2030));
    } catch (e) {
      return e;
    }
    return null;
  }

  test(
      'a relay answering anything but the one sealed answer is unreachable, with a retry sentence, never a trust refusal',
      () async {
    for (final status in [500, 502, 503, 504, 404]) {
      final e = await callThrough(
          MockClient((_) async => http.Response('busy', status)));
      expect(e, isA<AppUnreachable>(), reason: '$status');
      expect((e as AppUnreachable).status, status);
      expect(e.message, contains('Try again'));
      expect(e.message, isNot(contains('trust')));
    }
  });

  test('a 200 that does not open is still a refusal to trust', () async {
    final e = await callThrough(MockClient(
        (_) async => http.Response('{"v":1,"n":"AAAA","ct":"AAAA"}', 200)));
    expect(e, isA<TrustRefused>());
  });

  test(
      'only a signed 409 clock answer carries a time, and a malformed one carries none',
      () {
    DateTime now = DateTime.utc(2030, 1, 1, 0, 0, 0);
    SealedAnswer a(int status, String body) => (
          status: status,
          contentType: 'application/json',
          body: utf8.encode(body)
        );
    expect(
        clockAnswerSkew(
            a(409, '{"error":"clock","server_time":"2030-01-01T00:03:00Z"}'),
            now),
        const Duration(minutes: 3));
    expect(
        clockAnswerSkew(
            a(200, '{"error":"clock","server_time":"2030-01-01T00:03:00Z"}'),
            now),
        isNull);
    expect(clockAnswerSkew(a(409, '{"error":"other"}'), now), isNull);
    expect(
        clockAnswerSkew(
            a(409, '{"error":"clock","server_time":"yesterday"}'), now),
        isNull);
    expect(clockAnswerSkew(a(409, 'not json'), now), isNull);
  });
}
