import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/signing_an_event.dart';
import 'package:agent_client/services/the_event_this_device_expects.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

import 'support/a_signature_read_back.dart';
import 'support/the_core.dart';

// Every service in this package signs an event of an identity's log through
// signAndRecordEvent. What it records must be a signature over exactly the
// bytes the core serialised, against the event it names, and anything short of
// a recorded signature is an error rather than a quiet return.
/// A key arithmetic that reads every event as [parsed], standing in for the
/// core's parser, which has its own tests: here only what signAndRecordEvent
/// does with its verdict is under test. Every other operation, the writing of
/// a signature included, is the real core's, or [refusesToIndex] says it
/// cannot be done.
class _ReadsEveryEventAs implements KeyMath {
  _ReadsEveryEventAs(this.parsed, this.real, {this.refusesToIndex = false});
  final Map<String, dynamic> parsed;
  final KeyMath real;
  final bool refusesToIndex;
  @override
  Future<Map<String, dynamic>> run(String op, Map<String, dynamic> request) async {
    if (op == 'parse_event') return parsed;
    if (refusesToIndex) throw KeyMathRefused(op, 'the signature could not be written');
    return real.run(op, request);
  }
}

final _parsed = {
  't': 'ixn',
  'd': 'Ed',
  'i': 'Eaid',
  's': 3,
  'p': 'Eprior',
  'fields': [
    {'name': 'a', 'value': []},
  ],
};

void main() {
  late KeyMath real;
  late KeyMath km;
  setUpAll(() async {
    real = await keyMathOf(await buildTheCore('signing-an-event-core'));
    km = _ReadsEveryEventAs(_parsed, real);
  });

  final expected = ExpectedEvent.interaction(aid: 'Eaid', sn: 3, prior: 'Eprior', anchors: const []);
  final seed = Uint8List.fromList(List.generate(32, (i) => i));
  final event = utf8.encode('{"t":"rot","s":"3"}');
  final pub = ed.public(ed.newKeyFromSeed(seed));

  late List<http.Request> sent;
  http.Client core({int record = 200}) => MockClient((req) async {
        sent.add(req);
        return http.Response('{}', record);
      });

  setUp(() => sent = []);

  test('the signature recorded is over the event bytes, against the event named', () async {
    final cesr = await signAndRecordEvent(core(), 'http://core.test',
        aid: 'Eaid', sequenceNumber: 3, rawBytesB64: base64Encode(event), signingSeed: seed, what: 'this rotation', km: km, expected: expected);
    final recorded = jsonDecode(sent.last.body) as Map<String, dynamic>;
    expect(sent.last.url.path, '/api/events/signature');
    expect(recorded, {'aid': 'Eaid', 'sequence_number': 3, 'cesr_signature': cesr});
    expect(ed.verify(pub, Uint8List.fromList(event), rawOfIndexedSignature(cesr)), isTrue);
  });

  test('an event the core did not name is never signed', () async {
    for (final (aid, sn, raw) in [('', 3, 'eA'), ('Eaid', null, 'eA'), ('Eaid', '3', 'eA'), ('Eaid', 3, '')]) {
      await expectLater(
          signAndRecordEvent(core(), 'http://core.test',
              aid: aid, sequenceNumber: sn, rawBytesB64: raw, signingSeed: seed, what: 'this rotation', km: km, expected: expected),
          throwsException);
    }
    expect(sent, isEmpty);
  });

  test('an event that is not the one expected is never signed or recorded', () async {
    final other = ExpectedEvent.interaction(aid: 'Eaid', sn: 3, prior: 'Eprior', anchors: const [
      {'d': 'Esomethingelse'}
    ]);
    await expectLater(
        signAndRecordEvent(core(), 'http://core.test',
            aid: 'Eaid', sequenceNumber: 3, rawBytesB64: base64Encode(event), signingSeed: seed,
            what: 'this interaction', km: km, expected: other),
        throwsA(isA<AStoredEventIsNotTheOneExpected>()
            .having((e) => e.stored, 'stored', utf8.decode(event))
            .having((e) => e.expected['a'], 'expected', [
          {'d': 'Esomethingelse'}
        ])));
    // Nor is an event that is another place than the one the core named.
    await expectLater(
        signAndRecordEvent(core(), 'http://core.test',
            aid: 'Eaid', sequenceNumber: 4, rawBytesB64: base64Encode(event), signingSeed: seed,
            what: 'this interaction', km: km, expected: expected),
        throwsA(isA<AStoredEventIsNotTheOneExpected>()));
    expect(sent, isEmpty);
  });

  test('a signature that cannot be encoded or is refused is an error', () async {
    await expectLater(
        signAndRecordEvent(core(), 'http://core.test',
            aid: 'Eaid', sequenceNumber: 3, rawBytesB64: base64Encode(event), signingSeed: seed, what: 'this rotation',
            km: _ReadsEveryEventAs(_parsed, real, refusesToIndex: true), expected: expected),
        throwsA(predicate((e) => '$e'.contains('this rotation could not be signed'))));
    expect(sent.any((r) => r.url.path == '/api/events/signature'), isFalse);
    await expectLater(
        signAndRecordEvent(core(record: 400), 'http://core.test',
            aid: 'Eaid', sequenceNumber: 3, rawBytesB64: base64Encode(event), signingSeed: seed, what: 'this rotation', km: km, expected: expected),
        throwsA(predicate((e) => '$e'.contains('the signature over this rotation was refused'))));
  });
}
