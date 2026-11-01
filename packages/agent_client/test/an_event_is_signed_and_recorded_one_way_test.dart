import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/services/signing_an_event.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

// Every service in this package signs an event of an identity's log through
// signAndRecordEvent. What it records must be a signature over exactly the
// bytes the core serialised, against the event it names, and anything short of
// a recorded signature is an error rather than a quiet return.
void main() {
  final seed = Uint8List.fromList(List.generate(32, (i) => i));
  final event = utf8.encode('{"t":"rot","s":"3"}');
  final pub = ed.public(ed.newKeyFromSeed(seed));

  late List<http.Request> sent;
  http.Client core({int encode = 200, int record = 200}) => MockClient((req) async {
        sent.add(req);
        final body = jsonDecode(req.body) as Map<String, dynamic>;
        if (req.url.path == '/api/cesr/encode') {
          return http.Response(jsonEncode({'cesr_sig': body['raw_sig_b64']}), encode);
        }
        return http.Response('{}', record);
      });

  setUp(() => sent = []);

  test('the signature recorded is over the event bytes, against the event named', () async {
    final cesr = await signAndRecordEvent(core(), 'http://core.test',
        aid: 'Eaid', sequenceNumber: 3, rawBytesB64: base64Encode(event), signingSeed: seed, what: 'this rotation');
    final recorded = jsonDecode(sent.last.body) as Map<String, dynamic>;
    expect(sent.last.url.path, '/api/events/signature');
    expect(recorded, {'aid': 'Eaid', 'sequence_number': 3, 'cesr_signature': cesr});
    expect(ed.verify(pub, Uint8List.fromList(event), base64Decode(cesr)), isTrue);
  });

  test('an event the core did not name is never signed', () async {
    for (final (aid, sn, raw) in [('', 3, 'eA'), ('Eaid', null, 'eA'), ('Eaid', '3', 'eA'), ('Eaid', 3, '')]) {
      await expectLater(
          signAndRecordEvent(core(), 'http://core.test',
              aid: aid, sequenceNumber: sn, rawBytesB64: raw, signingSeed: seed, what: 'this rotation'),
          throwsException);
    }
    expect(sent, isEmpty);
  });

  test('a signature that cannot be encoded or is refused is an error', () async {
    await expectLater(
        signAndRecordEvent(core(encode: 500), 'http://core.test',
            aid: 'Eaid', sequenceNumber: 3, rawBytesB64: base64Encode(event), signingSeed: seed, what: 'this rotation'),
        throwsA(predicate((e) => '$e'.contains('this rotation could not be signed'))));
    expect(sent.any((r) => r.url.path == '/api/events/signature'), isFalse);
    await expectLater(
        signAndRecordEvent(core(record: 400), 'http://core.test',
            aid: 'Eaid', sequenceNumber: 3, rawBytesB64: base64Encode(event), signingSeed: seed, what: 'this rotation'),
        throwsA(predicate((e) => '$e'.contains('the signature over this rotation was refused'))));
  });
}
