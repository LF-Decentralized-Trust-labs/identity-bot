import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/crypto/owner_signature.dart';
import 'package:agent_client/services/owner_signing_client.dart';
import 'package:http/http.dart' as http;
import 'package:test/test.dart';

/// Records what it was asked to send, and answers nothing interesting.
class _Recorder extends http.BaseClient {
  http.BaseRequest? last;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    last = request;
    return http.StreamedResponse(const Stream.empty(), 200);
  }
}

Uint8List seedOf(int b) => Uint8List.fromList(List.filled(32, b));

void main() {
  const agent = 'https://my-agent.example.org';

  group('signing your own agent', () {
    test('a request to your own agent is signed', () async {
      final recorder = _Recorder();
      final client = OwnerSigningClient(
        agentOrigin: agent,
        ownerSeed: () async => seedOf(1),
        inner: recorder,
      );

      await client.post(Uri.parse('$agent/api/contacts'), body: '{"a":1}');

      expect(recorder.last!.headers, contains(OwnerSignature.sigHeader));
      expect(recorder.last!.headers, contains(OwnerSignature.timestampHeader));
    });

    test('the body survives being signed', () async {
      // Rebuilding the request to attach headers is where a body gets lost, and
      // a request that arrives empty fails in a way that looks like the server.
      final recorder = _Recorder();
      final client = OwnerSigningClient(
        agentOrigin: agent,
        ownerSeed: () async => seedOf(1),
        inner: recorder,
      );

      await client.post(Uri.parse('$agent/api/contacts'), body: '{"hello":"world"}');

      final sent = recorder.last as http.Request;
      expect(utf8.decode(sent.bodyBytes), '{"hello":"world"}');
    });

    test('the identifier is sent when known and omitted when not', () async {
      final withAid = _Recorder();
      await OwnerSigningClient(
        agentOrigin: agent,
        ownerSeed: () async => seedOf(1),
        ownerAid: 'EOwner',
        inner: withAid,
      ).get(Uri.parse('$agent/api/info'));
      expect(withAid.last!.headers[OwnerSignature.aidHeader], 'EOwner');

      final without = _Recorder();
      await OwnerSigningClient(
        agentOrigin: agent,
        ownerSeed: () async => seedOf(1),
        inner: without,
      ).get(Uri.parse('$agent/api/info'));
      expect(without.last!.headers.containsKey(OwnerSignature.aidHeader), isFalse);
    });
  });

  group('not signing anybody else', () {
    test('a request to a stranger carries no signature', () async {
      // The same client resolves other people's discovery records and talks to
      // relays and witnesses. Signing those would hand your identifier to every
      // stranger you look up.
      final recorder = _Recorder();
      final client = OwnerSigningClient(
        agentOrigin: agent,
        ownerSeed: () async => seedOf(1),
        inner: recorder,
      );

      await client.get(Uri.parse('https://someone-else.example.com/oobi/EThem'));

      expect(recorder.last!.headers.containsKey(OwnerSignature.sigHeader), isFalse,
          reason: 'an owner signature was sent to a host that is not your agent');
    });

    test('a lookalike host is not your agent', () async {
      // A prefix test would accept this, and being handed somebody else's
      // signature is exactly what that mistake costs.
      final recorder = _Recorder();
      final client = OwnerSigningClient(
        agentOrigin: agent,
        ownerSeed: () async => seedOf(1),
        inner: recorder,
      );

      await client.get(Uri.parse('https://my-agent.example.org.attacker.test/api/info'));

      expect(recorder.last!.headers.containsKey(OwnerSignature.sigHeader), isFalse,
          reason: 'a lookalike hostname was treated as your own agent');
    });

    test('a different port is a different agent', () async {
      final recorder = _Recorder();
      final client = OwnerSigningClient(
        agentOrigin: 'http://127.0.0.1:5050',
        ownerSeed: () async => seedOf(1),
        inner: recorder,
      );

      await client.get(Uri.parse('http://127.0.0.1:9999/api/info'));

      expect(recorder.last!.headers.containsKey(OwnerSignature.sigHeader), isFalse);
    });
  });

  group('when there is no seed', () {
    test('the request goes unsigned rather than failing', () async {
      // A locked device or an identity not yet created. The agent refuses it,
      // which is a clearer outcome than an exception from the transport.
      final recorder = _Recorder();
      final client = OwnerSigningClient(
        agentOrigin: agent,
        ownerSeed: () async => null,
        inner: recorder,
      );

      await client.get(Uri.parse('$agent/api/info'));

      expect(recorder.last, isNotNull, reason: 'the request never left');
      expect(recorder.last!.headers.containsKey(OwnerSignature.sigHeader), isFalse);
    });
  });

  group('what gets signed', () {
    test('the signed path carries no host and no query', () async {
      // The agent signs the same thing. A signature over a full URL would break
      // the moment the same agent were reached by another name, which is what
      // happens behind a relay.
      final recorder = _Recorder();
      final client = OwnerSigningClient(
        agentOrigin: agent,
        ownerSeed: () async => seedOf(7),
        inner: recorder,
      );

      await client.get(Uri.parse('$agent/api/contacts?since=yesterday'));
      final sent = recorder.last!;

      final expected = OwnerSignature.headers(
        method: 'GET',
        path: '/api/contacts',
        body: const [],
        ownerSeed: seedOf(7),
        now: DateTime.parse('${sent.headers[OwnerSignature.timestampHeader]}'),
      );
      expect(sent.headers[OwnerSignature.sigHeader], expected[OwnerSignature.sigHeader],
          reason: 'the query string leaked into what was signed');
    });

    test('two requests do not reuse a signature', () async {
      // The agent spends each signature once. Reusing one would be refused as a
      // replay, which reads as an intermittent failure rather than a bug.
      final recorder = _Recorder();
      final client = OwnerSigningClient(
        agentOrigin: agent,
        ownerSeed: () async => seedOf(1),
        inner: recorder,
      );

      await client.post(Uri.parse('$agent/api/contacts'), body: '{"a":1}');
      final first = recorder.last!.headers[OwnerSignature.sigHeader];
      await client.post(Uri.parse('$agent/api/contacts'), body: '{"a":2}');
      final second = recorder.last!.headers[OwnerSignature.sigHeader];

      expect(first, isNot(second));
    });
  });
}
