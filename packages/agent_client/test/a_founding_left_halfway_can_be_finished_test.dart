import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/services/core_service.dart';
import 'package:agent_client/services/the_key_in_force.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

/// Finishing a founding that was interrupted.
///
/// Founding is two acts — the identity is created, then it is signed — and
/// anything between them can fail: a timeout, the application killed, a machine
/// that slept. What is left is an identity nobody can verify, and given the
/// words it was founded from it is fixable, because the bytes are kept.
///
/// THE KEY HISTORY COMES BACK IN TWO SHAPES and the one that matters is the one
/// the first version of this could not read. An agent with the key engine beside
/// it — which is the only kind that can found at all — answers with the engine's
/// own events, the bytes in a separate list aligned by position, and the
/// sequence as text. Reading only the other shape made this fail every time.
void main() {
  const agent = 'http://127.0.0.1:5050';
  final seed = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));
  final key = AgentKeyPair.fromSigningSeed(seed).publicKeyEncoded;
  final next = AgentKeyPair.fromSigningSeed(Uint8List.fromList(List<int>.generate(32, (i) => i + 2))).publicKeyEncoded;

  /// A founding as the engine writes one, committing to [commitsTo] and any
  /// [more] commitments, anchoring [anchors].
  String foundingBytes({String? commitsTo, List<String> more = const [], List<Object?> anchors = const []}) =>
      jsonEncode({
        'v': 'KERI10JSON', 't': 'icp', 'd': 'EIDENTITY', 'i': 'EIDENTITY', 's': '0',
        'kt': '1', 'k': [key], 'nt': '1', 'n': [TheKeyInForce.commitmentTo(commitsTo ?? next), ...more],
        'bt': '0', 'b': [], 'c': [], 'a': anchors,
      });

  /// An agent that creates the founding [bytes].
  CoreService agentFounding(String bytes, List<http.BaseRequest> sent) => CoreService(
        baseUrl: agent,
        inner: MockClient((req) async {
          sent.add(req);
          if (req.url.path == '/api/inception') {
            return http.Response(
                jsonEncode({'aid': 'EIDENTITY', 'public_key': key, 'raw_bytes_b64': base64Encode(utf8.encode(bytes))}),
                201);
          }
          return http.Response(jsonEncode({'cesr_sig': '0Bx'}), 200);
        }),
      );

  /// The engine's own shape: bytes beside the events, sequence as text.
  String theEngineShape({String sequence = '0', String? commitsTo}) => jsonEncode({
        'aid': 'EIDENTITY',
        'kel': [
          {'v': 'KERI10JSON', 't': 'icp', 'i': 'EIDENTITY', 's': sequence},
        ],
        'raw_events_b64': [base64Encode(utf8.encode(foundingBytes(commitsTo: commitsTo)))],
      });

  /// The embedded shape: bytes on the event, sequence as a number.
  String theEmbeddedShape() => jsonEncode({
        'aid': 'EIDENTITY',
        'kel': [
          {
            'sequence_number': 0,
            'event_type': 'icp',
            'raw_bytes_b64': base64Encode(utf8.encode(foundingBytes())),
          },
        ],
      });

  CoreService coreThatAnswers(String kel, List<http.BaseRequest> sent,
      {int attachStatus = 200}) {
    return CoreService(
      baseUrl: agent,
      inner: MockClient((req) async {
        sent.add(req);
        if (req.url.path == '/api/kel') return http.Response(kel, 200);
        if (req.url.path == '/api/cesr/encode') {
          return http.Response(jsonEncode({'cesr_sig': '0BTHESIGNATURE'}), 200);
        }
        if (req.url.path == '/api/events/signature') {
          return http.Response('{}', attachStatus);
        }
        return http.Response('no', 404);
      }),
    );
  }

  test('the engine shape is read — bytes beside the events, sequence as text',
      () async {
    final sent = <http.BaseRequest>[];
    await coreThatAnswers(theEngineShape(), sent).signTheFoundingOf('EIDENTITY', seed, nextPublicKey: next);

    final attach = sent.firstWhere((r) => r.url.path == '/api/events/signature')
        as http.Request;
    final body = jsonDecode(attach.body) as Map<String, dynamic>;
    expect(body['aid'], 'EIDENTITY');
    expect(body['sequence_number'], 0);
    expect(body['cesr_signature'], '0BTHESIGNATURE');
  });

  test('and so is the embedded shape', () async {
    final sent = <http.BaseRequest>[];
    await coreThatAnswers(theEmbeddedShape(), sent)
        .signTheFoundingOf('EIDENTITY', seed, nextPublicKey: next);
    expect(sent.any((r) => r.url.path == '/api/events/signature'), isTrue);
  });

  test('a history with no founding event is refused rather than guessed at',
      () async {
    // Neither shape promises an order, and signing the wrong event fails at the
    // agent with a complaint about the signature — which sends somebody looking
    // at the signing rather than at the choosing.
    final sent = <http.BaseRequest>[];
    final kel = jsonEncode({
      'aid': 'EIDENTITY',
      'kel': [
        {'t': 'rot', 's': '1'},
      ],
      'raw_events_b64': [base64Encode(utf8.encode('a rotation'))],
    });
    expect(
      coreThatAnswers(kel, sent).signTheFoundingOf('EIDENTITY', seed, nextPublicKey: next),
      throwsA(predicate((e) => '$e'.contains('does not contain a founding'))),
    );
  });

  test('an event with no bytes anywhere is refused', () async {
    final sent = <http.BaseRequest>[];
    final kel = jsonEncode({
      'aid': 'EIDENTITY',
      'kel': [
        {'t': 'icp', 's': '0'},
      ],
    });
    expect(
      coreThatAnswers(kel, sent).signTheFoundingOf('EIDENTITY', seed, nextPublicKey: next),
      throwsA(predicate((e) => '$e'.contains('without the bytes'))),
    );
  });

  test('a refusal from the agent is surfaced, not swallowed', () async {
    final sent = <http.BaseRequest>[];
    expect(
      coreThatAnswers(theEngineShape(), sent, attachStatus: 400)
          .signTheFoundingOf('EIDENTITY', seed, nextPublicKey: next),
      throwsA(isA<Exception>()),
    );
  });

  test('a founding that commits to somebody else\'s next key is never signed', () async {
    final sent = <http.BaseRequest>[];
    final stranger = AgentKeyPair.fromSigningSeed(Uint8List(32)).publicKeyEncoded;
    await expectLater(
      coreThatAnswers(theEngineShape(commitsTo: stranger), sent)
          .signTheFoundingOf('EIDENTITY', seed, nextPublicKey: next),
      throwsA(predicate((e) => '$e'.contains('not the one this device asked for'))),
    );
    expect(sent.any((r) => r.url.path == '/api/cesr/encode'), isFalse);
  });

  test('nor is one created that way', () async {
    final sent = <http.BaseRequest>[];
    final stranger = AgentKeyPair.fromSigningSeed(Uint8List(32)).publicKeyEncoded;
    final core = CoreService(
      baseUrl: agent,
      inner: MockClient((req) async {
        sent.add(req);
        if (req.url.path == '/api/inception') {
          return http.Response(
              jsonEncode({
                'aid': 'EIDENTITY',
                'public_key': key,
                'raw_bytes_b64': base64Encode(utf8.encode(foundingBytes(commitsTo: stranger))),
              }),
              201);
        }
        return http.Response(jsonEncode({'cesr_sig': '0Bx'}), 200);
      }),
    );
    await expectLater(core.createInception(publicKey: key, nextPublicKey: next, signingSeed: seed),
        throwsA(predicate((e) => '$e'.contains('not the one this device asked for'))));
    expect(sent.any((r) => r.url.path == '/api/cesr/encode'), isFalse);
  });

  test('a founding of another identifier is never signed', () async {
    final sent = <http.BaseRequest>[];
    await expectLater(
      coreThatAnswers(theEngineShape(), sent).signTheFoundingOf('ESOMEBODYELSE', seed, nextPublicKey: next),
      throwsA(predicate((e) => '$e'.contains('not the one this device asked for'))),
    );
    expect(sent.any((r) => r.url.path == '/api/cesr/encode'), isFalse);
  });

  test('a founding naming an owner other than the one asked for is never signed', () async {
    const asked = 'EOWNERASKEDFOR';
    const other = 'ESOMEBODYELSE';
    var sent = <http.BaseRequest>[];
    await expectLater(
        agentFounding(foundingBytes(anchors: [{'i': other, 's': '0', 'd': other}]), sent)
            .createInception(publicKey: key, nextPublicKey: next, signingSeed: seed, ownerAid: asked),
        throwsA(predicate((e) => '$e'.contains('owner'))));
    expect(sent.any((r) => r.url.path == '/api/cesr/encode'), isFalse);
    sent = [];
    await agentFounding(foundingBytes(anchors: [{'i': asked, 's': '0', 'd': asked}]), sent)
        .createInception(publicKey: key, nextPublicKey: next, signingSeed: seed, ownerAid: asked);
    expect(sent.any((r) => r.url.path == '/api/cesr/encode'), isTrue);
  });

  test('what the agent adds of its own is accepted only where it was given the phrase', () async {
    final bytes = foundingBytes(more: ['Epostquantum'], anchors: [
      {'ia': 'IA-HYBRID-1', 'ka': ['C'], 'sa': ['D']}
    ]);
    var sent = <http.BaseRequest>[];
    await expectLater(agentFounding(bytes, sent).createInception(publicKey: key, nextPublicKey: next, signingSeed: seed),
        throwsA(predicate((e) => '$e'.contains('was not given this phrase'))));
    expect(sent.any((r) => r.url.path == '/api/cesr/encode'), isFalse);
    for (final one in [
      foundingBytes(more: ['Epostquantum']),
      foundingBytes(anchors: [
        {'ia': 'IA-HYBRID-1', 'ka': ['C'], 'sa': ['D']}
      ]),
    ]) {
      sent = [];
      await expectLater(agentFounding(one, sent).createInception(publicKey: key, nextPublicKey: next, signingSeed: seed),
          throwsA(predicate((e) => '$e'.contains('was not given this phrase'))),
          reason: 'either addition alone, from a core not given the phrase');
      expect(sent.any((r) => r.url.path == '/api/cesr/encode'), isFalse);
    }
    sent = [];
    await agentFounding(bytes, sent)
        .createInception(publicKey: key, nextPublicKey: next, signingSeed: seed, theCoreWasGivenThisPhrase: true);
    expect(sent.any((r) => r.url.path == '/api/cesr/encode'), isTrue);
  });
}
