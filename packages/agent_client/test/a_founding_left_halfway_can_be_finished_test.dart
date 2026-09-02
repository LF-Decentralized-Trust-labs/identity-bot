import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/services/core_service.dart';
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

  /// The engine's own shape: bytes beside the events, sequence as text.
  String theEngineShape({String sequence = '0'}) => jsonEncode({
        'aid': 'EIDENTITY',
        'kel': [
          {'v': 'KERI10JSON', 't': 'icp', 'i': 'EIDENTITY', 's': sequence},
        ],
        'raw_events_b64': [base64Encode(utf8.encode('the founding bytes'))],
      });

  /// The embedded shape: bytes on the event, sequence as a number.
  String theEmbeddedShape() => jsonEncode({
        'aid': 'EIDENTITY',
        'kel': [
          {
            'sequence_number': 0,
            'event_type': 'icp',
            'raw_bytes_b64': base64Encode(utf8.encode('the founding bytes')),
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
    await coreThatAnswers(theEngineShape(), sent).signTheFoundingOf('EIDENTITY', seed);

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
        .signTheFoundingOf('EIDENTITY', seed);
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
      coreThatAnswers(kel, sent).signTheFoundingOf('EIDENTITY', seed),
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
      coreThatAnswers(kel, sent).signTheFoundingOf('EIDENTITY', seed),
      throwsA(predicate((e) => '$e'.contains('without the bytes'))),
    );
  });

  test('a refusal from the agent is surfaced, not swallowed', () async {
    final sent = <http.BaseRequest>[];
    expect(
      coreThatAnswers(theEngineShape(), sent, attachStatus: 400)
          .signTheFoundingOf('EIDENTITY', seed),
      throwsA(isA<Exception>()),
    );
  });
}
