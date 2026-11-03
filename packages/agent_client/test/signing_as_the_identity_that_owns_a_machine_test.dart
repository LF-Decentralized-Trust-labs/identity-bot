import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:agent_client/crypto/owner_signature.dart';
import 'package:agent_client/services/controller_signing_client.dart' show ThisMachineCouldNotSign;
import 'package:agent_client/services/signing_as_the_identity_that_owns_a_machine.dart';
import 'package:agent_client/services/the_core_is_settled.dart';
import 'package:test/test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart' as testing;

const _machine = 'https://box.example.test';
const _core = 'http://127.0.0.1:5050';

/// Records every request, and answers the local core's signing call.
class _Watcher {
  final requests = <http.BaseRequest>[];
  Map<String, dynamic>? signAsked;

  /// What the local core will answer with. Null means it refuses.
  Map<String, dynamic>? signature = const {
    'owner_aid': 'EMINTEDHERE',
    'signature': '0BSIG',
    'timestamp': '2026-09-01T00:00:00Z',
  };

  http.Client get client => testing.MockClient((req) async {
        requests.add(req);
        if (req.url.path == '/api/machines/owner/sign') {
          signAsked = jsonDecode(req.body) as Map<String, dynamic>;
          if (signature == null) return http.Response('no', 403);
          return http.Response(jsonEncode(signature), 200);
        }
        return http.Response('{}', 200);
      });
}

Future<String?> Function() _owner(String? aid) => () async => aid;

void main() {
  test('the request names the Identity Agent the core signed it for', () async {
    final w = _Watcher()
      ..signature = const {
        'owner_aid': 'EMINTEDHERE',
        'signature': '0BSIG',
        'timestamp': '2026-09-01T00:00:00Z',
        'for': 'ETHEMACHINE',
      };
    final c = SigningAsTheIdentityThatOwnsAMachine(
      machineOrigin: _machine,
      localCoreOrigin: () => _core,
      ownerAid: _owner('EMINTEDHERE'),
      inner: w.client,
    );
    await c.get(Uri.parse('$_machine/api/identity'));
    expect(w.requests.last.headers['X-IA-Owner-For'], 'ETHEMACHINE',
        reason: 'the name inside the signature was not sent, so the machine '
            'checks a different string and refuses every request');
  });

  test('a request to the machine carries a signature made for it', () async {
    final w = _Watcher();
    final c = SigningAsTheIdentityThatOwnsAMachine(
      machineOrigin: _machine,
      localCoreOrigin: () => _core,
      ownerAid: _owner('EMINTEDHERE'),
      inner: w.client,
    );

    await c.post(Uri.parse('$_machine/api/rotation'), body: '{"x":1}');

    expect(w.signAsked, isNotNull);
    expect(w.signAsked!['owner_aid'], 'EMINTEDHERE');
    expect(w.signAsked!['method'], 'POST');
    // The path only. A signature over a full URL breaks the moment the same
    // machine is reached by a different name, which is what a relay does.
    expect(w.signAsked!['path'], '/api/rotation');
    expect(utf8.decode(base64.decode(w.signAsked!['body_b64'] as String)),
        '{"x":1}');

    final sent = w.requests.last;
    expect(sent.url.toString(), '$_machine/api/rotation');
    expect(sent.headers['X-IA-Owner-Sig'], '0BSIG');
    expect(sent.headers['X-IA-Owner-AID'], 'EMINTEDHERE');
    // Echoed from the core, not formatted again here: the moment is inside the
    // signature, so a second formatting signs a string the machine never sees.
    expect(sent.headers['X-IA-Owner-Timestamp'], '2026-09-01T00:00:00Z');
    // The digest the signature covers, so the machine checks the signature
    // before reading any of the body: Blake3 of the bytes that were sent.
    expect(sent.headers['X-IA-Body-Digest'],
        OwnerSignature.blake3QB64(utf8.encode('{"x":1}')));
  });

  test('nothing else is signed, however similar the name', () async {
    final w = _Watcher();
    final c = SigningAsTheIdentityThatOwnsAMachine(
      machineOrigin: _machine,
      localCoreOrigin: () => _core,
      ownerAid: _owner('EMINTEDHERE'),
      inner: w.client,
    );

    // A prefix test would accept this as the machine, which is a real way to be
    // handed this identity's signature.
    await c.get(Uri.parse('https://box.example.test.attacker.test/api/identity'));
    // And an ordinary lookup of somebody else's discovery record. Attaching an
    // identifier to those hands it to every stranger this app looks up, which
    // is the opposite of what a pairwise identifier is for.
    await c.get(Uri.parse('https://witness.example.test/oobi/EOTHER'));

    expect(w.signAsked, isNull);
    for (final r in w.requests) {
      expect(r.headers.containsKey('X-IA-Owner-Sig'), isFalse);
    }
  });

  tearDown(TheCoreIsSettled.reset);

  SigningAsTheIdentityThatOwnsAMachine owning(http.Client inner,
          {String? Function()? core, String? aid = 'EMINTEDHERE'}) =>
      SigningAsTheIdentityThatOwnsAMachine(
        machineOrigin: _machine,
        localCoreOrigin: () => core?.call() ?? _core,
        ownerAid: _owner(aid),
        waitAtMost: const Duration(milliseconds: 200),
        inner: inner,
      );

  test('a machine this device does not own is refused, never sent unsigned',
      () async {
    final w = _Watcher();
    final c = owning(w.client, aid: null);
    await expectLater(c.get(Uri.parse('$_machine/api/identity')),
        throwsA(isA<ThisMachineCouldNotSign>()));
    expect(w.signAsked, isNull);
    expect(w.requests, isEmpty);
    final empty = owning(w.client, aid: '');
    await expectLater(empty.get(Uri.parse('$_machine/api/identity')),
        throwsA(isA<ThisMachineCouldNotSign>()));
    expect(w.requests, isEmpty);
  });

  test('a core that will not sign refuses the request', () async {
    final w = _Watcher()..signature = null;
    await expectLater(owning(w.client).get(Uri.parse('$_machine/api/identity')),
        throwsA(isA<ThisMachineCouldNotSign>()));
    expect(w.signAsked, isNotNull);
    expect(w.requests.where((r) => r.url.host == 'box.example.test'), isEmpty);
  });

  test('an answer that is not a signature refuses the request', () async {
    for (final answer in [
      '{}',
      '{"signature":"0B"}',
      '{"timestamp":"t"}',
      'not json',
      '[1]',
    ]) {
      final sent = <http.BaseRequest>[];
      final c = owning(testing.MockClient((req) async {
        if (req.url.path == '/api/machines/owner/sign') {
          return http.Response(answer, 200);
        }
        sent.add(req);
        return http.Response('{}', 200);
      }));
      await expectLater(c.get(Uri.parse('$_machine/api/identity')),
          throwsA(isA<ThisMachineCouldNotSign>()),
          reason: 'the core answered $answer');
      expect(sent, isEmpty, reason: 'sent unsigned after $answer');
    }
  });

  test('an unreachable core refuses the request', () async {
    final sent = <http.BaseRequest>[];
    final c = owning(testing.MockClient((req) async {
      if (req.url.path == '/api/machines/owner/sign') {
        throw const SocketException('connection refused');
      }
      sent.add(req);
      return http.Response('{}', 200);
    }));
    await expectLater(c.get(Uri.parse('$_machine/api/identity')),
        throwsA(isA<ThisMachineCouldNotSign>()));
    expect(sent, isEmpty);
  });

  test('a streamed body is signed, not passed through', () async {
    final w = _Watcher();
    final streamed = http.StreamedRequest('POST', Uri.parse('$_machine/api/up'))
      ..sink.add(utf8.encode('{"big":1}'))
      ..sink.close();
    await owning(w.client).send(streamed);
    expect(w.requests.last.headers['X-IA-Owner-Sig'], '0BSIG');
    expect(utf8.decode(base64.decode(w.signAsked!['body_b64'] as String)),
        '{"big":1}');
  });

  test('a multipart upload is signed and reaches the machine with its boundary',
      () async {
    final w = _Watcher();
    final m = http.MultipartRequest('POST', Uri.parse('$_machine/api/up'))
      ..fields['a'] = 'b';
    await owning(w.client).send(m);
    final sent = w.requests.last;
    expect(sent.headers['content-type'], startsWith('multipart/form-data; boundary='));
    expect(sent.headers['X-IA-Owner-Sig'], '0BSIG');
  });

  test('it signs at the core\'s address now, not the one it was built with',
      () async {
    final asked = <String>[];
    var core = 'http://127.0.0.1:5050';
    final c = owning(testing.MockClient((req) async {
      if (req.url.path == '/api/machines/owner/sign') {
        asked.add(req.url.origin);
        return http.Response(
            jsonEncode({'signature': '0B', 'timestamp': 't'}), 200);
      }
      return http.Response('{}', 200);
    }), core: () => core);
    await c.get(Uri.parse('$_machine/api/identity'));
    core = 'http://127.0.0.1:50555';
    await c.get(Uri.parse('$_machine/api/identity'));
    expect(asked, ['http://127.0.0.1:5050', 'http://127.0.0.1:50555']);
  });

  test('a request waits while the core is being switched, and a start that '
      'failed refuses it', () async {
    final w = _Watcher();
    final c = owning(w.client);
    final starting = Completer<void>();
    final during = TheCoreIsSettled.during(() => starting.future);
    var done = false;
    final pending = c
        .get(Uri.parse('$_machine/api/identity'))
        .whenComplete(() => done = true);
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(done, isFalse);
    expect(w.signAsked, isNull);
    starting.complete();
    await during;
    await pending;
    expect(w.signAsked, isNotNull);

    await expectLater(
        TheCoreIsSettled.during<void>(() async => throw StateError('no')),
        throwsStateError);
    await expectLater(c.get(Uri.parse('$_machine/api/identity')),
        throwsA(isA<ThisMachineCouldNotSign>()));
  });

  group('which identity adopted a machine', () {
    http.Client listing(List<Map<String, dynamic>> agents) =>
        testing.MockClient((req) async {
          if (req.url.path == '/api/agents') {
            return http.Response(jsonEncode({'agents': agents}), 200);
          }
          return http.Response('{}', 404);
        });

    test('is matched on the address, not on the text of it', () async {
      // Recorded with a trailing slash, called without one. Comparing the
      // strings misses the row and leaves the request unsigned with nothing
      // saying why.
      final read = theIdentityThatAdopted(
        _machine,
        localCoreOrigin: () => _core,
        using: listing([
          {'url': 'https://other.example.test', 'owner_aid': 'ENOPE'},
          {'url': '$_machine/', 'owner_aid': 'EMINTEDHERE'},
        ]),
      );
      expect(await read(), 'EMINTEDHERE');
    });

    test('a machine the root owns has no pairwise identity to sign as',
        () async {
      // Adopted before machines were adopted pairwise. An answer, not a gap —
      // and one this client cannot act on, so it must not guess.
      final read = theIdentityThatAdopted(
        _machine,
        localCoreOrigin: () => _core,
        using: listing([
          {'url': _machine, 'owner_aid': ''},
        ]),
      );
      expect(await read(), isNull);
    });

    test('a machine this device does not own is null', () async {
      final read = theIdentityThatAdopted(
        _machine,
        localCoreOrigin: () => _core,
        using: listing(const []),
      );
      expect(await read(), isNull);
    });
  });
}
