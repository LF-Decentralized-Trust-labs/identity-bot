import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/services/core_service.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/the_event_this_device_expects.dart';
import 'package:agent_client/services/the_key_in_force.dart';
import 'package:agent_client/services/the_witnesses_of_this_devices_events.dart' show WitnessSet;
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

import 'support/kel_events.dart';
import 'support/the_core.dart';

/// Finishing a founding that was interrupted.
///
/// Founding is two acts: the identity is created, then it is signed. What an
/// earlier version left between them is a stored founding nobody signed; given
/// the words it was founded from it is fixable, because the bytes are kept.
/// Those bytes are checked with the core's own parser, as a new event's are,
/// before they are signed.
///
/// THE KEY HISTORY COMES BACK IN TWO SHAPES and the one that matters is the one
/// the first version of this could not read. An agent with the key engine beside
/// it answers with the engine's own events, the bytes in a separate list aligned
/// by position, and the sequence as text. Reading only the other shape made this
/// fail every time.
void main() {
  const agent = 'http://127.0.0.1:5050';
  // The BIP39 seed of a phrase: the founding is checked against what that
  // phrase makes (key 0, a commitment to key 1).
  final seed = Bip39.mnemonicToSeed(
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
          .split(' '));
  final key = KeyManager.publicKeyAt(seed, 0);
  final next = KeyManager.publicKeyAt(seed, 1);
  late KeyMath km;

  setUpAll(() async {
    km = await keyMathOf(await buildTheCore('founding-left-halfway-core'));
  });

  /// A founding as the engine writes one (the digest and identifier are real),
  /// committing to [commitsTo] and any [more] commitments, anchoring [anchors].
  List<int> foundingBytes(
          {String? commitsTo,
          List<String> more = const [],
          List<Object?> anchors = const []}) =>
      saidified({
        't': 'icp',
        'd': '',
        'i': '',
        's': '0',
        'kt': '1',
        'k': [key],
        'nt': '1',
        'n': [TheKeyInForce.commitmentTo(commitsTo ?? next), ...more],
        'bt': '0',
        'b': [],
        'c': [],
        'a': anchors,
      });

  String aidOf(List<int> bytes) => '${(jsonDecode(utf8.decode(bytes)) as Map)['i'] ?? 'EIDENTITY'}';

  /// The engine's own shape: bytes beside the events, sequence as text.
  String theEngineShape(List<int> bytes, {String sequence = '0'}) => jsonEncode({
        'aid': aidOf(bytes),
        'kel': [
          {'v': 'KERI10JSON', 't': 'icp', 'i': aidOf(bytes), 's': sequence},
        ],
        'raw_events_b64': [base64Encode(bytes)],
      });

  /// The embedded shape: bytes on the event, sequence as a number.
  String theEmbeddedShape(List<int> bytes) => jsonEncode({
        'aid': aidOf(bytes),
        'kel': [
          {
            'sequence_number': 0,
            'event_type': 'icp',
            'raw_bytes_b64': base64Encode(bytes),
          },
        ],
      });

  CoreService coreThatAnswers(String kel, List<http.BaseRequest> sent,
      {int attachStatus = 200}) {
    return CoreService(
      baseUrl: agent,
      keyMath: km,
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

  bool signed(List<http.BaseRequest> sent) =>
      sent.any((r) => r.url.path == '/api/cesr/encode');

  test('the engine shape is read — bytes beside the events, sequence as text',
      () async {
    final sent = <http.BaseRequest>[];
    final bytes = foundingBytes();
    await coreThatAnswers(theEngineShape(bytes), sent)
        .signTheFoundingOf(aidOf(bytes), seed);

    final attach = sent.firstWhere((r) => r.url.path == '/api/events/signature')
        as http.Request;
    final body = jsonDecode(attach.body) as Map<String, dynamic>;
    expect(body['aid'], aidOf(bytes));
    expect(body['sequence_number'], 0);
    expect(body['cesr_signature'], '0BTHESIGNATURE');
  });

  test('and so is the embedded shape', () async {
    final sent = <http.BaseRequest>[];
    final bytes = foundingBytes();
    await coreThatAnswers(theEmbeddedShape(bytes), sent)
        .signTheFoundingOf(aidOf(bytes), seed);
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
      coreThatAnswers(kel, sent)
          .signTheFoundingOf('EIDENTITY', seed),
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
      coreThatAnswers(kel, sent)
          .signTheFoundingOf('EIDENTITY', seed),
      throwsA(predicate((e) => '$e'.contains('without the bytes'))),
    );
  });

  test('a refusal from the agent is surfaced, not swallowed', () async {
    final sent = <http.BaseRequest>[];
    final bytes = foundingBytes();
    expect(
      coreThatAnswers(theEngineShape(bytes), sent, attachStatus: 400)
          .signTheFoundingOf(aidOf(bytes), seed),
      throwsA(isA<Exception>()),
    );
  });

  test('a founding that commits to somebody else\'s next key is never signed',
      () async {
    final sent = <http.BaseRequest>[];
    final stranger =
        AgentKeyPair.fromSigningSeed(Uint8List(32)).publicKeyEncoded;
    final bytes = foundingBytes(commitsTo: stranger);
    await expectLater(
      coreThatAnswers(theEngineShape(bytes), sent)
          .signTheFoundingOf(aidOf(bytes), seed),
      throwsA(isA<AStoredEventIsNotTheOneExpected>()
          .having((e) => e.stored, 'stored', utf8.decode(bytes))
          .having((e) => e.expected['n'], 'expected', [
        await km.nextKeyDigest(next)
      ])),
    );
    expect(signed(sent), isFalse);
  });

  test('a founding of another identifier is never signed', () async {
    final sent = <http.BaseRequest>[];
    final bytes = foundingBytes();
    await expectLater(
      coreThatAnswers(theEngineShape(bytes), sent)
          .signTheFoundingOf('ESOMEBODYELSE', seed),
      throwsA(isA<AStoredEventIsNotTheOneExpected>()),
    );
    expect(signed(sent), isFalse);
  });

  test('a founding naming an owner other than the one asked for is never signed',
      () async {
    const asked = 'EOWNERASKEDFOR';
    const other = 'ESOMEBODYELSE';
    var sent = <http.BaseRequest>[];
    final wrong = foundingBytes(anchors: [
      {'i': other, 's': '0', 'd': other}
    ]);
    await expectLater(
        coreThatAnswers(theEngineShape(wrong), sent).signTheFoundingOf(
            aidOf(wrong), seed, ownerAid: asked),
        throwsA(isA<AStoredEventIsNotTheOneExpected>()));
    expect(signed(sent), isFalse);
    sent = [];
    final right = foundingBytes(anchors: [
      {'i': asked, 's': '0', 'd': asked}
    ]);
    await coreThatAnswers(theEngineShape(right), sent).signTheFoundingOf(
        aidOf(right), seed, ownerAid: asked);
    expect(signed(sent), isTrue);
  });

  test('what the agent adds of its own to a founding is never signed',
      () async {
    for (final one in [
      foundingBytes(more: [
        'Epostquantum'
      ], anchors: [
        {'ia': 'IA-HYBRID-1', 'ka': ['C'], 'sa': ['D']}
      ]),
      foundingBytes(more: ['Epostquantum']),
      foundingBytes(anchors: [
        {'ia': 'IA-HYBRID-1', 'ka': ['C'], 'sa': ['D']}
      ]),
    ]) {
      final sent = <http.BaseRequest>[];
      await expectLater(
          coreThatAnswers(theEngineShape(one), sent)
              .signTheFoundingOf(aidOf(one), seed),
          throwsA(isA<AStoredEventIsNotTheOneExpected>()),
          reason:
              'a commitment or anchor the core added would be a key of that machine\'s');
      expect(signed(sent), isFalse);
    }
  });

  test('a founding as the old /api/inception made it is signed here as it is when the log is finished, and one on another branch is not',
      () async {
    // The same builder as TheKeyInForce.finishStrandedEvents uses: the owner
    // seal and the messaging keyset of the first allocation, committing also to
    // the post-quantum key (Go's values: test/support/legacy_founding_golden.json).
    final golden = jsonDecode(
            File('test/support/legacy_founding_golden.json').readAsStringSync())
        as Map<String, dynamic>;
    const owner = 'EOWNERNAMEDBYTHEPERSON';
    Map<String, dynamic> owned() => {'i': owner, 's': '0', 'd': owner};
    var sent = <http.BaseRequest>[];
    final old = foundingBytes(more: [
      golden['post_quantum_digest'] as String
    ], anchors: [
      owned(),
      golden['messaging_anchor_at_5000001']
    ]);
    await coreThatAnswers(theEngineShape(old), sent)
        .signTheFoundingOf(aidOf(old), seed, ownerAid: owner);
    expect(signed(sent), isTrue);

    sent = [];
    final other = foundingBytes(more: [
      golden['post_quantum_digest'] as String
    ], anchors: [
      owned(),
      golden['messaging_anchor_at_1']
    ]);
    await expectLater(
        coreThatAnswers(theEngineShape(other), sent)
            .signTheFoundingOf(aidOf(other), seed, ownerAid: owner),
        throwsA(isA<AStoredEventIsNotTheOneExpected>()));
    expect(signed(sent), isFalse);
  });

  test('a founding with witnesses other than the ones this device knows is never signed',
      () async {
    final sent = <http.BaseRequest>[];
    final bytes = saidified({
      't': 'icp', 'd': '', 'i': '', 's': '0', 'kt': '1', 'k': [key], 'nt': '1',
      'n': [TheKeyInForce.commitmentTo(next)], 'bt': '1',
      'b': ['B${'A' * 43}'], 'c': [], 'a': [],
    });
    await expectLater(
        coreThatAnswers(theEngineShape(bytes), sent).signTheFoundingOf(
            aidOf(bytes), seed,
            witnesses: WitnessSet(['B${'Z' * 43}'], 1)),
        throwsA(isA<AStoredEventIsNotTheOneExpected>()));
    expect(signed(sent), isFalse);
    await coreThatAnswers(theEngineShape(bytes), sent).signTheFoundingOf(
        aidOf(bytes), seed,
        witnesses: WitnessSet(['B${'A' * 43}'], 1));
    expect(signed(sent), isTrue);
  });

  test('bytes that are no event at all are never signed', () async {
    final sent = <http.BaseRequest>[];
    final bytes = utf8.encode('{"t":"icp","s":"0"}');
    await expectLater(
        coreThatAnswers(theEngineShape(bytes), sent)
            .signTheFoundingOf('EIDENTITY', seed),
        throwsA(isA<NotTheEventExpected>()));
    expect(signed(sent), isFalse);
  });
}
