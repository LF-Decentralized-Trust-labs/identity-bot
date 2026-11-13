import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:login_dart/app_checks.dart';
import 'package:login_dart/seal.dart';
import 'package:login_dart/witnessed.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

// The Dart port of sealed front-end traffic is held to the cases the TypeScript
// (login-web/src/seal.ts) and the Go (login-go/seal.go) run, byte for byte
// (packages/login-web/test-vectors/seal.json).

final v =
    jsonDecode(File('../login-web/test-vectors/seal.json').readAsStringSync())
        as Map<String, dynamic>;

Uint8List unb64(String s) => b64uDecode(s)!;
Uint8List unb16(String h) => Uint8List.fromList([
      for (var i = 0; i < h.length; i += 2)
        int.parse(h.substring(i, i + 2), radix: 16)
    ]);
BigInt big(String hex) => BigInt.parse(hex, radix: 16);
List<Map<String, dynamic>> of(String k) =>
    (v[k] as List).cast<Map<String, dynamic>>();

void main() {
  test('the log a relay identifier\u2019s witnesses vouch for, case by case',
      () {
    final w = v['witnessed'] as Map<String, dynamic>;
    final cases = (w['cases'] as List).cast<Map<String, dynamic>>();
    expect(cases.length, greaterThanOrEqualTo(10));
    for (final c in cases) {
      final rid = c['rid'] as String;
      final answers = c['answers'] as List<Object?>;
      if (c['refuse'] == true) {
        expect(
            () => readWitnessedLog(rid, answers), throwsA(isA<TrustRefused>()),
            reason: 'witnessed: ${c['name']}');
      } else {
        expect(readWitnessedLog(rid, answers).events, c['events'],
            reason: 'witnessed: ${c['name']}');
      }
    }
  });

  test('the log a link carried, against the log its witnesses vouch for', () {
    final w = v['witnessed'] as Map<String, dynamic>;
    final cases = (w['against_link'] as List).cast<Map<String, dynamic>>();
    expect(cases.length, greaterThanOrEqualTo(4));
    for (final c in cases) {
      expect(
          judgeLinkLog(c['rid'] as String, c['link_log'] as String,
                  c['answers'] as List<Object?>)
              .verdict
              .name,
          c['verdict'],
          reason: 'against the link: ${c['name']}');
    }
  });

  test('a link that names witnesses is taken or refused by what they answer',
      () async {
    final w = v['witnessed'] as Map<String, dynamic>;
    final cases = (w['page'] as List).cast<Map<String, dynamic>>();
    expect(cases.length, greaterThanOrEqualTo(4));
    final spk0 = unb64((v['seal_key'] as Map)['public_b64u'] as String);
    for (final c in cases) {
      final held = {
        'https://w0.example/api': (c['held'] as Map)['w0'],
        'https://w1.example/api': (c['held'] as Map)['w1'],
      };
      final client = MockClient((req) async {
        final a =
            held[req.url.toString().replaceAll(RegExp(r'/witness/kel/.*'), '')];
        if (a == 'down') throw http.ClientException('network down');
        if (a == null) return http.Response('not held', 404);
        return http.Response(jsonEncode(a), 200);
      });
      final link = AppLink(
          '',
          '',
          c['rid'] as String,
          'https://tasks.example',
          c['statement'] as String,
          c['min'] as String,
          (c['wit'] as List).cast<String>());
      final take = checkedSealKeyWitnessed(link, AnswerLogs(), client);
      if (c['expect'] == 'taken') {
        expect(await take, spk0, reason: 'a page: ${c['name']}');
      } else {
        await expectLater(
            take,
            throwsA(isA<TrustRefused>().having((e) => e.message, 'message',
                contains('moved on since this link was made'))),
            reason: 'a page: ${c['name']}');
      }
    }
  });

  test(
      'a sealing key is checked once, and a refused one is never taken as checked',
      () async {
    final w = v['witnessed'] as Map<String, dynamic>;
    final cases = (w['page'] as List).cast<Map<String, dynamic>>();
    final taken = cases.firstWhere(
        (c) => c['expect'] == 'taken' && (c['held'] as Map)['w0'] != 'down');
    final refused = cases.firstWhere((c) => c['expect'] == 'moved_on');
    int asked = 0;
    http.Client clientFor(Map<String, dynamic> c) {
      final held = {
        'https://w0.example/api': (c['held'] as Map)['w0'],
        'https://w1.example/api': (c['held'] as Map)['w1'],
      };
      return MockClient((req) async {
        asked++;
        final a =
            held[req.url.toString().replaceAll(RegExp(r'/witness/kel/.*'), '')];
        return a == null
            ? http.Response('no', 404)
            : http.Response(jsonEncode(a), 200);
      });
    }

    AppLink linkOf(Map<String, dynamic> c) => AppLink(
        '',
        '',
        c['rid'] as String,
        'https://tasks.example',
        c['statement'] as String,
        c['min'] as String,
        (c['wit'] as List).cast<String>());
    final once = CheckedSealKey(linkOf(taken), AnswerLogs(), clientFor(taken));
    await once.get();
    final after = asked;
    expect(after, greaterThan(0));
    await once.get();
    expect(asked, after,
        reason:
            'a key already checked is not checked, or the witnesses asked, again');

    // A refused link is refused every time it is tried, never taken as checked.
    final again =
        CheckedSealKey(linkOf(refused), AnswerLogs(), clientFor(refused));
    await expectLater(again.get(), throwsA(isA<TrustRefused>()));
    await expectLater(again.get(), throwsA(isA<TrustRefused>()));
  });

  final rid = v['rid'] as String;
  final spk = unb64((v['seal_key'] as Map)['public_b64u'] as String);
  final serverD = big((v['seal_key'] as Map)['private_hex'] as String);

  test(
      'the link’s sealing key is vouched for by the relay identifier’s current key log',
      () {
    final st = (v['seal_key'] as Map)['statement'] as String;
    final ok = checkSealKey(rid, st);
    expect(ok.key, spk);
    expect(ok.log, v['relay_log']);
    expect(checkSealKey(rid, st, known: v['relay_log'] as String).key, spk);
    final min = (v['seal_key'] as Map)['min'] as String;
    // a page that has seen nothing is held to the link's latest event, and an unreadable memory is replaced by it
    expect(checkSealKey(rid, st, min: min).log, v['relay_log']);
    expect(checkSealKey(rid, st, known: '!!', min: min).log, v['relay_log']);
    expect(
        () => checkSealKey(rid, st, known: '!!'),
        throwsA(isA<TrustRefused>()
            .having((e) => e.message, 'message', contains('cannot be read'))));
    final refusals = of('statement_refusals');
    expect(refusals.length, greaterThanOrEqualTo(10));
    for (final c in refusals) {
      expect(
          () => checkSealKey(c['rid'] as String, c['statement'] as String,
              known: c['known_log'] as String?, min: c['min'] as String?),
          throwsA(isA<TrustRefused>().having(
              (e) => e.message, 'message', contains('sealing key is refused'))),
          reason: 'a statement: ${c['name']}');
    }
  });

  test(
      'every request case: the call sealed, opened, and its answer sealed and opened, byte for byte',
      () {
    for (final c in of('requests')) {
      final name = c['name'];
      final s = sealRequest(rid, spk, utf8.encode(c['content'] as String),
          ephemeral: big(c['eph_d_hex'] as String));
      expect(s.outer, c['outer'], reason: '$name: the call sealed');
      final o = openRequest(rid, serverD, c['outer'] as String);
      expect(utf8.decode(o.content), c['content'],
          reason: '$name: the call opened');
      expect(
          o.reply.seal(utf8.encode(c['answer_content'] as String),
              n: unb16(c['answer_n_hex'] as String)),
          c['answer_outer'],
          reason: '$name: the answer sealed');
      expect(utf8.decode(s.reply.open(c['answer_outer'] as String)),
          c['answer_content'],
          reason: '$name: the answer opened');
    }
  });

  test('every refusal is refused', () {
    for (final c in of('refusals')) {
      expect(
          () => openRequest(c['rid'] as String, serverD, c['outer'] as String),
          throwsA(isA<SealRefused>()),
          reason: '${c['name']}');
    }
    for (final c in of('answer_refusals')) {
      final r = of('requests').firstWhere((q) => q['name'] == c['request']);
      final s = sealRequest(rid, spk, utf8.encode(r['content'] as String),
          ephemeral: big(r['eph_d_hex'] as String));
      expect(() => s.reply.open(c['answer_outer'] as String),
          throwsA(isA<SealRefused>()),
          reason: 'an answer: ${c['name']}');
    }
  });

  test('a ciphertext is its bucket and 16 bytes of tag, and nothing finer', () {
    for (final z in of('sizes')) {
      final s = sealRequest(rid, spk, Uint8List(z['content_len'] as int));
      final ct = unb64((jsonDecode(s.outer) as Map)['ct'] as String);
      expect(ct.length, z['ct_len'], reason: '${z['content_len']} bytes');
    }
    expect(() => sealRequest(rid, spk, Uint8List(sealMax + 1)),
        throwsA(isA<SealRefused>()));
    expect(() => sealRequest(rid, Uint8List(65), [1]),
        throwsA(isA<SealRefused>()));
  });

  test(
      'an answer value out of bounds, another version, a point that is not on the curve and a message that declares too much are refused',
      () {
    final r = of('requests').first;
    final s = sealRequest(rid, spk, utf8.encode(r['content'] as String),
        ephemeral: big(r['eph_d_hex'] as String));
    final o = openRequest(rid, serverD, r['outer'] as String);
    expect(() => o.reply.seal([1], n: Uint8List(answerNMin - 1)),
        throwsA(isA<SealRefused>()));
    expect(() => o.reply.seal([1], n: Uint8List(answerNMax + 1)),
        throwsA(isA<SealRefused>()));
    final answer = jsonDecode(o.reply.seal([1])) as Map<String, dynamic>;
    expect(s.reply.open(jsonEncode(answer)), [1]);
    expect(() => s.reply.open(jsonEncode({...answer, 'v': 2})),
        throwsA(isA<SealRefused>()));
    // not on the curve (x and y are below the field prime), and a coordinate that is not below the prime
    expect(
        () => sealRequest(
            rid,
            Uint8List.fromList(
                [4, ...List.filled(31, 0), 1, ...List.filled(31, 0), 1]),
            [1]),
        throwsA(isA<SealRefused>()));
    final p = unb16(
        'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
    expect(
        () => sealRequest(
            rid, Uint8List.fromList([4, ...p, ...Uint8List(32)]), [1]),
        throwsA(isA<SealRefused>()));
    final n = sealMax + 1;
    var want = sealBucket;
    while (want < n + 4) {
      want *= 2;
    }
    final padded = Uint8List(want)..buffer.asByteData().setUint32(0, n);
    expect(() => unpadForTest(padded), throwsA(isA<SealRefused>()));
  });

  test('the clock answer is the shared one', () {
    final ca = v['clock_answer'] as Map<String, dynamic>;
    final now = DateTime.parse(ca['now'] as String);
    SealedAnswer a(int status, String body) => (
          status: status,
          contentType: 'application/json',
          body: utf8.encode(body)
        );
    expect(clockAnswerSkew(a(ca['status'] as int, ca['body'] as String), now),
        Duration(milliseconds: ca['skew_ms'] as int));
    for (final c
        in (ca['not_clock_answers'] as List).cast<Map<String, dynamic>>()) {
      expect(clockAnswerSkew(a(c['status'] as int, c['body'] as String), now),
          isNull,
          reason: c['name'] as String);
    }
  });
}
