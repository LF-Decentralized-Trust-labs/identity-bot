import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:login_dart/app_checks.dart';
import 'package:test/test.dart';

// The Dart port of the login SDK's app checks is held to the cases the SDK's
// TypeScript runs (identity-bot packages/login-web/test-vectors/app-checks.json,
// beside it): every case must give the same answer here. A
// case with `refuse` is refused with a message containing that text; any other
// gives `expect`. A change to a rule is made there, in the vectors, and in
// lib/app_checks.dart together, never here alone.

// APP_CHECKS_VECTORS names another file: the vectors of a core not yet pinned.
final cases = jsonDecode(File(Platform.environment['APP_CHECKS_VECTORS'] ??
        '../login-web/test-vectors/app-checks.json')
    .readAsStringSync()) as Map<String, dynamic>;

Uint8List hex(String h) => Uint8List.fromList([
      for (var i = 0; i < h.length; i += 2) int.parse(h.substring(i, i + 2), radix: 16)
    ]);

String hexOf(List<int> b) => b.map((v) => v.toRadixString(16).padLeft(2, '0')).join();

List<Map<String, dynamic>> of(String k) =>
    (cases[k] as List).cast<Map<String, dynamic>>();

/// Runs [f] and holds it to the case: refused with the text, or [check]ed.
void hold(Map<String, dynamic> c, Object? Function() f, void Function(Object?) check) {
  final why = c['refuse'] as String?;
  if (why == null) {
    check(f());
    return;
  }
  expect(f, throwsA(isA<TrustRefused>().having((e) => e.message, 'message', contains(why))),
      reason: '${c['name']}');
}

void main() {
  test('every link case', () {
    for (final c in of('links')) {
      hold(c, () => AppLink.parse(c['hash'] as String), (r) {
        final l = r as AppLink;
        final e = c['expect'] as Map<String, dynamic>;
        expect([l.aid, l.kel, l.rid, l.api, l.seal, l.min], [e['aid'], e['kel'], e['rid'], e['api'], e['seal'], e['min']], reason: '${c['name']}');
      });
    }
  });

  test('every key log case', () {
    for (final c in of('key_logs')) {
      hold(c, () => checkKeyLog(c['aid'] as String, c['encoded'] as String),
          (r) => expect(hexOf(r as List<int>), c['expect_key_hex'], reason: '${c['name']}'));
    }
  });

  test('every challenge case', () {
    for (final c in of('challenges')) {
      hold(c, () => checkChallenge(
          aid: c['aid'] as String,
          key: hex(c['key_hex'] as String),
          body: c['body'],
          sig: c['sig'],
          pointer: c['pointer'],
          ownThumbprint: c['own_thumbprint'] as String,
          now: DateTime.fromMillisecondsSinceEpoch(c['now_ms'] as int, isUtc: true)), (r) {
        final got = r as Map<String, dynamic>;
        final e = c['expect'] as Map<String, dynamic>;
        for (final k in e.keys) {
          expect(got[k], e[k], reason: '${c['name']} $k');
        }
        if (!e.containsKey('front_end')) expect(got.containsKey('front_end'), isFalse);
      });
    }
  });

  test('every answer case', () {
    for (final c in of('answers')) {
      hold(c, () => checkAnswer(
          rid: c['rid'] as String,
          nonce: c['nonce'] as String,
          status: c['status'] as int,
          contentType: c['content_type'] as String,
          body: base64.decode(c['body_b64'] as String),
          log: c['log'] as String?,
          known: c['known'] as String?,
          sig: c['sig'] as String?), (r) => expect(r, c['expect_log'], reason: '${c['name']}'));
    }
  });

  test('every proof, answer text, thumbprint and clock case', () {
    for (final c in of('proofs')) {
      expect(
          backEndProofString(c['method'] as String, c['target'] as String, c['ts'] as String,
              c['nonce'] as String, c['binding'] as String, utf8.encode(c['body'] as String)),
          c['expect']);
    }
    for (final c in of('answer_texts')) {
      expect(
          answerText(c['rid'] as String, c['nonce'] as String, c['status'] as int,
              c['content_type'] as String, base64.decode(c['body_b64'] as String)),
          c['expect']);
    }
    for (final c in of('thumbprints')) {
      expect(browserKeyThumbprint(c['x'] as String, c['y'] as String), c['expect']);
    }
    for (final c in of('skews')) {
      hold(c, () => serverSkew(c['server_time'],
          DateTime.fromMillisecondsSinceEpoch(c['now_ms'] as int, isUtc: true)),
          (r) => expect((r as Duration).inMilliseconds, c['expect_ms']));
    }
  });

  test('a challenge for another kind of front end is refused by an installed app too', () {
    final c = of('challenges').firstWhere((c) => c['name'] == 'a challenge naming the browser kind');
    expect(
        () => checkChallenge(
            aid: c['aid'] as String,
            key: hex(c['key_hex'] as String),
            body: c['body'],
            sig: c['sig'],
            pointer: c['pointer'],
            ownThumbprint: c['own_thumbprint'] as String,
            now: DateTime.fromMillisecondsSinceEpoch(c['now_ms'] as int, isUtc: true),
            frontEnd: 'installed_app'),
        throwsA(isA<TrustRefused>()));
  });
}
