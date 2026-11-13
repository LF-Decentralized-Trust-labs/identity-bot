import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:login_dart/app_checks.dart';
import 'package:login_dart/seal.dart';
import 'package:test/test.dart';

// A routine rotation of the relay identifier moves the sealing key, and an
// installed front end holding the old one is not stranded: the back end says the
// key a call was sealed to has moved on, the front end fetches the statement now
// in force, checks it as it checks a link's, seals the same call to it once, and
// only then, if that fails, says the link is out of date. The cases are the
// `sealing_key_answer` and `rotation` ones of the shared vectors
// (packages/login-web/test-vectors/seal.json), which the TypeScript and the Go run.

final v =
    jsonDecode(File('../login-web/test-vectors/seal.json').readAsStringSync())
        as Map<String, dynamic>;

Uint8List unb64(String s) => b64uDecode(s)!;
BigInt big(String hex) => BigInt.parse(hex, radix: 16);

void main() {
  final rid = v['rid'] as String;
  final r = v['rotation'] as Map<String, dynamic>;
  final old = r['old'] as Map<String, dynamic>;
  final fresh = r['new'] as Map<String, dynamic>;
  final freshD = big(fresh['private_hex'] as String);
  final oldKey = unb64(old['public_b64u'] as String);
  final newKey = unb64(fresh['public_b64u'] as String);
  final linkMin = old['min'] as String;
  AppLink linkOf() => AppLink('', '', rid, 'https://tasks.example',
      old['statement'] as String, linkMin);

  Future<Object?> callOnce(CheckedSealKey sealing, http.Client c,
      {List<int>? body}) async {
    try {
      await sealedCallDated(c, linkOf(), sealing,
          logs: AnswerLogs(),
          now: () => DateTime.utc(2030),
          make: (skew) async => (
                method: 'POST',
                target: '/api/mcp/agents/a/conversations',
                headers: <String, String>{},
                body: body ?? utf8.encode('{"text":"the message being sent"}'),
                nonce: 'abcdefghijkl',
              ));
    } catch (e) {
      return e;
    }
    return null;
  }

  test('the sealing key answer is the shared one', () {
    final a = v['sealing_key_answer'] as Map<String, dynamic>;
    expect(isSealingKeyAnswer(a['status'] as int, a['body'] as String), isTrue);
    expect(sealStatementPath, a['statement_path']);
    for (final c in (a['not_sealing_key_answers'] as List)
        .cast<Map<String, dynamic>>()) {
      expect(
          isSealingKeyAnswer(c['status'] as int, c['body'] as String), isFalse,
          reason: c['name'] as String);
    }
  });

  test(
      'the statement now in force is taken, and the statement before it is not',
      () {
    final got = checkSealKey(rid, fresh['statement'] as String,
        known: v['relay_log'] as String, min: linkMin);
    expect(got.key, newKey);
    expect(got.log, fresh['log']);
    expect(
        () => checkSealKey(rid, old['statement'] as String,
            known: fresh['log'] as String, min: linkMin),
        throwsA(isA<TrustRefused>()));
    expect(() => openRequest(rid, freshD, r['old_outer'] as String),
        throwsA(isA<SealRefused>()));
    expect(openRequest(rid, freshD, r['new_outer'] as String).content,
        utf8.encode(r['content'] as String));
  });

  test(
      'a call made after a rotation is sealed again to the key now in force, once, with its text',
      () async {
    final opened = <String>[]; // what each POST was, as the back end saw it
    var gets = 0;
    final c = MockClient((req) async {
      if (req.method == 'GET') {
        expect(req.url.path, sealStatementPath);
        gets++;
        return http.Response(fresh['statement'] as String, 200);
      }
      expect(req.url.path, sealPath);
      try {
        final o = openRequest(rid, freshD, req.body);
        opened.add(utf8.decode(o.content));
        // the back end cannot answer in this test: say the relay failed, which
        // shows the call reached it and opened
        return http.Response('busy', 503);
      } on SealRefused {
        opened.add('did not open');
        return http.Response('{"error":"sealing key"}', 400,
            headers: {'content-type': 'application/json'});
      }
    });
    final sealing = CheckedSealKey(linkOf(), AnswerLogs(), c);
    expect(await sealing.get(), oldKey);
    final e = await callOnce(sealing, c);
    expect(e, isA<AppUnreachable>(),
        reason: 'the second send reached a back end that opened it');
    expect((e as AppUnreachable).status, 503);
    expect(gets, 1, reason: 'the statement is fetched once');
    expect(opened.length, 2);
    expect(opened[0], 'did not open');
    final inner = jsonDecode(opened[1]) as Map<String, dynamic>;
    expect(inner['body'], '{"text":"the message being sent"}',
        reason: 'what the person was sending is sent as it was');
    expect(await sealing.get(), newKey, reason: 'the new key is kept');
  });

  test(
      'a second "sealing key" answer is a link out of date, with one retry only',
      () async {
    var posts = 0, gets = 0;
    final c = MockClient((req) async {
      if (req.method == 'GET') {
        gets++;
        return http.Response(fresh['statement'] as String, 200);
      }
      posts++;
      return http.Response('{"error":"sealing key"}', 400);
    });
    final e = await callOnce(CheckedSealKey(linkOf(), AnswerLogs(), c), c);
    expect(e, isA<LinkOutOfDate>());
    expect((e as LinkOutOfDate).message, contains('out of date'));
    expect(e.message, contains('Identity Agent'));
    expect(posts, 2);
    expect(gets, 1);
  });

  test(
      'a statement that fails its checks is a link out of date, nothing is sent on it',
      () async {
    var posts = 0;
    for (final bad in [
      'AAAA',
      // the statement made before the rotation names the key the call just failed with
      // and is covered below; this one is the identifier's, at an earlier point, with
      // a minimum the link did not reach
    ]) {
      final c = MockClient((req) async {
        if (req.method == 'GET') return http.Response(bad, 200);
        posts++;
        return http.Response('{"error":"sealing key"}', 400);
      });
      final e = await callOnce(CheckedSealKey(linkOf(), AnswerLogs(), c), c);
      expect(e, isA<LinkOutOfDate>(), reason: bad);
      expect(posts, 1);
      posts = 0;
    }
  });

  test(
      'the relay failing to give the statement is unreachable, not out of date',
      () async {
    final c = MockClient((req) async => req.method == 'GET'
        ? http.Response('down', 503)
        : http.Response('{"error":"sealing key"}', 400));
    final e = await callOnce(CheckedSealKey(linkOf(), AnswerLogs(), c), c);
    expect(e, isA<AppUnreachable>());
    expect(e, isNot(isA<LinkOutOfDate>()));
  });

  test('a statement that names the key already held is not a rotation',
      () async {
    final c = MockClient((req) async => req.method == 'GET'
        ? http.Response(old['statement'] as String, 200)
        : http.Response('{"error":"sealing key"}', 400));
    final e = await callOnce(CheckedSealKey(linkOf(), AnswerLogs(), c), c);
    expect(e, isA<AppUnreachable>());
  });

  test('any other refusal is not a moved key: no statement is fetched',
      () async {
    var gets = 0;
    final c = MockClient((req) async {
      if (req.method == 'GET') gets++;
      return http.Response('{"error":"not accepted"}', 400);
    });
    final e = await callOnce(CheckedSealKey(linkOf(), AnswerLogs(), c), c);
    expect(e, isA<AppUnreachable>());
    expect(gets, 0);
  });
}
