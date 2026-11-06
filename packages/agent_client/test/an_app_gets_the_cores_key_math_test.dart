import 'dart:convert';

import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/mobile_core_service.dart';
import 'package:agent_client/services/the_cores_key_math.dart';
import 'package:flutter/services.dart';
import 'package:test/test.dart';

import 'support/the_core.dart';

/// An app obtains the core's key arithmetic one way (ADR-061 section 7): the
/// core linked into it on a phone, the bundled core binary on a desktop,
/// checked against the hash compiled into the app.
void main() {
  // What the channel does, as a phone's bridge would answer it.
  Future<String?> Function(String, Object?)? answer;
  final calls = <(String, Object?)>[];
  setUp(() {
    calls.clear();
    answer = null;
  });
  Future<String> throughTheChannel(String op, String request) =>
      MobileCoreService.keyMath(op, request, invoke: (method, args) {
        calls.add((method, args));
        final a = answer;
        // No handler: what an unregistered channel method raises.
        if (a == null) throw MissingPluginException();
        return a(method, args);
      });

  const sha =
      'ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12';

  test(
      'on a phone each operation goes to the core linked into the app as '
      'keyMath, with its op and request, and its answer comes back', () async {
    answer = (_, __) async => jsonEncode({'digest': 'Eabc'});
    final km = TheCoresKeyMath(mobile: true, mobileCall: throughTheChannel);
    expect(await km.run('next_key_digest', {'public_key': 'Dxyz'}),
        {'digest': 'Eabc'});
    expect(calls.single.$1, 'keyMath');
    final args = Map<String, Object?>.from(calls.single.$2 as Map);
    expect(args['op'], 'next_key_digest');
    expect(jsonDecode(args['request'] as String), {'public_key': 'Dxyz'});
  });

  test(
      'on a phone a refusal by the core is a KeyMathRefused carrying only '
      'the core\'s reason', () async {
    answer = (_, __) async => throw PlatformException(
        code: 'keymath_refused',
        message: 'not an event',
        details: 'details the native side should not have sent');
    final km = TheCoresKeyMath(mobile: true, mobileCall: throughTheChannel);
    await expectLater(
        km.run('parse_event', {'raw_b64': ''}),
        throwsA(isA<KeyMathRefused>()
            .having((e) => e.reason, 'reason', 'not an event')));
  });

  test('on a phone with no keyMath bridge nothing is read as a refusal',
      () async {
    // No handler: the channel answers MissingPluginException.
    final km = TheCoresKeyMath(mobile: true, mobileCall: throughTheChannel);
    await expectLater(
        km.run('next_key_digest', {}), throwsA(isA<KeyMathUnavailable>()));
  });

  test(
      'on a phone a bridge that fails otherwise, or answers nothing, is not '
      'a refusal either', () async {
    answer = (_, __) async => throw PlatformException(code: 'crashed');
    final km = TheCoresKeyMath(mobile: true, mobileCall: throughTheChannel);
    await expectLater(
        km.run('next_key_digest', {}), throwsA(isA<KeyMathUnavailable>()));
    answer = (_, __) async => null;
    await expectLater(
        TheCoresKeyMath(mobile: true, mobileCall: throughTheChannel)
            .run('next_key_digest', {}),
        throwsA(isA<KeyMathUnavailable>()));
  });

  test(
      'on a desktop the bundled binary is run with the hash the app was '
      'built with', () async {
    String? ran, withHash;
    final km = TheCoresKeyMath(
        mobile: false,
        expectedSha256: sha.toUpperCase(),
        bundledBinary: () => '/the/app/identity-agent-core',
        command: (b, h) {
          ran = b;
          withHash = h;
          return _Answering();
        });
    expect(await km.run('next_key_digest', {}), {'ok': true});
    expect((ran, withHash), ('/the/app/identity-agent-core', sha));
  });

  test(
      'a desktop app built without the hash runs nothing, and says which '
      'define is missing', () async {
    var made = false;
    final km = TheCoresKeyMath(
        mobile: false,
        expectedSha256: '',
        bundledBinary: () => '/the/app/identity-agent-core',
        command: (_, __) {
          made = true;
          return _Answering();
        });
    await expectLater(
        km.run('next_key_digest', {}),
        throwsA(isA<KeyMathBinaryRefused>().having((e) => e.reason, 'reason',
            contains('IDENTITY_AGENT_CORE_SHA256'))));
    expect(made, isFalse);
  });

  test('a desktop app with no bundled core runs nothing', () async {
    final km = TheCoresKeyMath(
        mobile: false, expectedSha256: sha, bundledBinary: () => null);
    await expectLater(
        km.run('next_key_digest', {}), throwsA(isA<KeyMathBinaryRefused>()));
  });

  test('a failed resolution is not remembered', () async {
    String? binary;
    final km = TheCoresKeyMath(
        mobile: false,
        expectedSha256: sha,
        bundledBinary: () => binary,
        command: (_, __) => _Answering());
    await expectLater(
        km.run('next_key_digest', {}), throwsA(isA<KeyMathBinaryRefused>()));
    binary = '/the/app/identity-agent-core';
    expect(await km.run('next_key_digest', {}), {'ok': true});
  });

  test(
      'the real core binary runs under the hash it was built with, and not '
      'under another', () async {
    final bin = await buildTheCore('cores-km');
    final digest = await sha256Of(bin);
    KeyMath real(String sha) => TheCoresKeyMath(
        mobile: false,
        expectedSha256: sha,
        bundledBinary: () => bin,
        command: (b, h) => CommandKeyMath(
            binaryPath: b, expectedSha256: h, signature: SignedByUs()));
    expect(await real(digest).run('pq_next', {'seed_hex': '11' * 32}),
        contains('digest'));
    await expectLater(
        real(sha).run('pq_next', {'seed_hex': '11' * 32}),
        throwsA(isA<KeyMathBinaryRefused>().having((e) => e.reason, 'reason',
            contains('not the binary this app was built with'))));
  });
}

class _Answering implements KeyMath {
  @override
  Future<Map<String, dynamic>> run(
          String op, Map<String, dynamic> request) async =>
      {'ok': true};
}
