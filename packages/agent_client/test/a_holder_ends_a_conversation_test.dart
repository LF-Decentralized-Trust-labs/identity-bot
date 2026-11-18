import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:agent_client/crypto/person_statement.dart';
import 'package:agent_client/services/a_holder_ends_a_conversation.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;
import 'package:test/test.dart';

Uint8List hex(String h) => Uint8List.fromList([
      for (var i = 0; i < h.length; i += 2)
        int.parse(h.substring(i, i + 2), radix: 16)
    ]);

class _Recorder extends http.BaseClient {
  http.Request? last;
  int status = 201;
  String answer = '{"state":"done"}';
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    last = request as http.Request;
    return http.StreamedResponse(Stream.value(utf8.encode(answer)), status);
  }
}

void main() {
  // The core's published vectors: what this client signs must be what the core
  // checks, byte for byte, or every statement it makes is refused.
  final vectors = jsonDecode(File(
          '../../identity-agent-core/agentmessage/signed-fingerprint-vectors.json')
      .readAsStringSync()) as Map<String, dynamic>;
  final seed = hex(vectors['seed_hex'] as String);

  test('the signer and verkey are the ones the vectors name for the seed', () {
    final priv = ed.newKeyFromSeed(seed);
    final pub = Uint8List.fromList(ed.public(priv).bytes);
    expect(PersonStatement.signerOf(pub), vectors['signer']);
    expect(PersonStatement.verkeyOf(pub), vectors['verkey']);
  });

  test('every published fingerprint is reproduced', () {
    for (final f in vectors['fingerprints'] as List) {
      expect(
          PersonStatement.fingerprintOf(
              hex(f['salt_hex']), hex(f['words_hex'])),
          f['fingerprint'],
          reason: f['name']);
    }
  });

  test('every published statement is signed to the same bytes and signature',
      () {
    for (final v in vectors['statements'] as List) {
      final s = v['statement'] as Map<String, dynamic>;
      final st = PersonStatement(
        agent: s['agent'],
        conversation: s['conversation'],
        messageId: s['message_id'],
        kind: s['kind'],
        from: s['from'],
        signer: s['signer'],
        to: s['to'] ?? '',
        inReplyTo: s['in_reply_to'] ?? '',
        rangeFirst: s['range_first'] ?? '',
        rangeLast: s['range_last'] ?? '',
        audience: s['audience'] ?? '',
        nonce: s['nonce'],
        time: s['time'],
        fingerprint: s['fingerprint'],
      );
      expect(utf8.decode(st.bytes()), v['signed'], reason: v['name']);
      expect(st.signedWith(seed)['signature'], v['signature'],
          reason: v['name']);
    }
  });

  test('a field with a line break is refused before anything is signed', () {
    final priv = ed.newKeyFromSeed(seed);
    final signer =
        PersonStatement.signerOf(Uint8List.fromList(ed.public(priv).bytes));
    for (final (brk, inNonce) in [
      ('\n', false),
      ('\r', false),
      ('\n', true),
    ]) {
      final st = PersonStatement(
        agent: 'EAGENT',
        conversation: inNonce ? 'c_one' : 'c_one${brk}close',
        messageId: 'm1',
        kind: PersonStatement.kindClose,
        from: 'EAGENT',
        signer: signer,
        nonce: inNonce ? 'n1${brk}n2' : 'n1',
        time: '2026-11-17T00:00:00Z',
        fingerprint: 'Efp',
      );
      expect(() => st.signedWith(seed), throwsArgumentError,
          reason: 'line break ${brk.codeUnitAt(0)} in the '
              '${inNonce ? 'nonce' : 'conversation'}');
    }
  });

  group('a holder closes a conversation', () {
    test('the request names the route, carries the statement and no words',
        () async {
      final rec = _Recorder();
      final done = await holderControlsAConversation(rec, 'https://core',
          identityAid: 'EIDENTITY',
          signingSeed: () async => seed,
          kind: 'close',
          conversation: 'c_one');
      expect(done.state, 'done');
      expect(rec.last!.url.path, '/api/mcp/conversations/c_one/close');
      final body = jsonDecode(rec.last!.body) as Map;
      expect(body['body'], '');
      String pad(String s) => s + '=' * ((4 - s.length % 4) % 4);
      final proof = jsonDecode(utf8.decode(base64Url
          .decode(pad(rec.last!.headers['X-IA-Person-Statement']!)))) as Map;
      final st = proof['statement'] as Map;
      expect(st['kind'], 'close');
      expect(st['from'], 'EIDENTITY');
      expect(st['agent'], 'EIDENTITY');
      expect(st['to'], isNull);
      expect(st['message_id'], body['nonce']);
      expect(proof['verkey'], vectors['verkey']);
      expect(st['signer'], vectors['signer']);
      final salt =
          base64Url.decode(pad(rec.last!.headers['X-IA-Person-Salt']!));
      expect(st['fingerprint'], PersonStatement.fingerprintOf(salt, const []));
    });

    test('a limit carries the number as its words, under the fingerprint',
        () async {
      final rec = _Recorder();
      await holderControlsAConversation(rec, 'https://core',
          identityAid: 'EIDENTITY',
          signingSeed: () async => seed,
          kind: 'limit',
          conversation: 'c_one',
          limit: 80);
      expect((jsonDecode(rec.last!.body) as Map)['body'], '80');
    });

    test(
        'a refusal is said in the core\'s words, and a limit with no number is not sent',
        () async {
      final rec = _Recorder()
        ..status = 403
        ..answer = '{"error":"only the one who opened"}';
      await expectLater(
          holderControlsAConversation(rec, 'https://core',
              identityAid: 'EIDENTITY',
              signingSeed: () async => seed,
              kind: 'reopen',
              conversation: 'c_one'),
          throwsA(isA<ConversationControlRefused>().having((e) => e.message,
              'message', contains('only the one who opened'))));
      expect(
          () => holderControlsAConversation(rec, 'https://core',
              identityAid: 'E',
              signingSeed: () async => seed,
              kind: 'limit',
              conversation: 'c'),
          throwsArgumentError);
    });
  });
}
