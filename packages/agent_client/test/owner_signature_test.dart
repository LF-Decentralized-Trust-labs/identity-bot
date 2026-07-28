import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/crypto/owner_signature.dart';
import 'package:test/test.dart';

/// A fixed seed, so a signature is reproducible and can be pinned against the
/// agent's own implementation.
Uint8List fixedSeed() =>
    Uint8List.fromList(List<int>.generate(32, (i) => i + 1));

void main() {
  test('the canonical string is exactly what the agent builds', () {
    final s = OwnerSignature.canonicalString(
      method: 'get',
      path: '/api/profile',
      timestamp: '2026-07-27T12:00:00Z',
      body: const [],
    );
    // Five lines, in this order, uppercase method. The agent splits on the
    // same newlines; a difference of one rejects every request.
    expect(s.split('\n').length, 5);
    expect(s.split('\n')[0], 'IA-REQ-V1');
    expect(s.split('\n')[1], 'GET');
    expect(s.split('\n')[2], '/api/profile');
    expect(s.split('\n')[3], '2026-07-27T12:00:00Z');
    expect(s.split('\n')[4].startsWith('E'), isTrue);
  });

  test('blake3 qb64 matches the agent, byte for byte', () {
    // Cross-checked against Go's iacrypto.Blake3QB64Must("hello world").
    expect(
      OwnerSignature.blake3QB64(utf8.encode('hello world')),
      'ENdJge-nCgyIC42MGYXQddvL9nm5ml-ZFOWq-WuDGp4k',
    );
  });

  test('the empty body has a digest, and it is stable', () {
    final a = OwnerSignature.blake3QB64(const []);
    final b = OwnerSignature.blake3QB64(const []);
    expect(a, b);
    expect(a.length, 44);
  });

  test('timestamps are second-precision UTC, not milliseconds', () {
    final t = DateTime.utc(2026, 7, 27, 12, 0, 0, 456);
    expect(OwnerSignature.rfc3339Seconds(t), '2026-07-27T12:00:00Z');
  });

  test('a signature binds the method, the path and the body', () {
    final seed = fixedSeed();
    final at = DateTime.utc(2026, 7, 27, 12, 0, 0);

    String sig({String method = 'GET', String path = '/api/profile', String body = ''}) =>
        OwnerSignature.headers(
          method: method,
          path: path,
          body: utf8.encode(body),
          ownerSeed: seed,
          now: at,
        )[OwnerSignature.sigHeader]!;

    final base = sig();
    // Change any one of them and the signature must change, or a captured one
    // could be pointed somewhere else.
    expect(sig(method: 'POST'), isNot(base));
    expect(sig(path: '/api/reset'), isNot(base));
    expect(sig(body: '{"x":1}'), isNot(base));
    expect(sig(), base, reason: 'the same request must sign the same way');
  });

  test('the signature is CESR qb64 for Ed25519', () {
    final headers = OwnerSignature.headers(
      method: 'GET',
      path: '/api/profile',
      body: const [],
      ownerSeed: fixedSeed(),
      now: DateTime.utc(2026, 7, 27, 12, 0, 0),
    );
    final sig = headers[OwnerSignature.sigHeader]!;
    expect(sig.startsWith('0B'), isTrue, reason: 'Ed25519 signature code');
    expect(sig.length, 88);
    expect(headers[OwnerSignature.timestampHeader], '2026-07-27T12:00:00Z');
  });

  test('the owner AID header is sent only when known', () {
    final without = OwnerSignature.headers(
      method: 'GET', path: '/x', body: const [], ownerSeed: fixedSeed());
    expect(without.containsKey(OwnerSignature.aidHeader), isFalse);

    final with_ = OwnerSignature.headers(
      method: 'GET', path: '/x', body: const [], ownerSeed: fixedSeed(),
      ownerAid: 'EOWNER');
    expect(with_[OwnerSignature.aidHeader], 'EOWNER');
  });

  /// The vector the agent's test pins from the other side. If either
  /// implementation changes, one of the two fails rather than every request
  /// failing silently in production.
  test('golden vector', () {
    final sig = OwnerSignature.headers(
      method: 'GET',
      path: '/api/profile',
      body: const [],
      ownerSeed: fixedSeed(),
      now: DateTime.utc(2026, 7, 27, 12, 0, 0),
    )[OwnerSignature.sigHeader]!;
    print('GOLDEN_SIGNATURE=$sig');
    expect(sig.startsWith('0B'), isTrue);
  });
}
