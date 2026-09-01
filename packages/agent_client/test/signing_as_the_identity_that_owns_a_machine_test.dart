import 'dart:convert';

import 'package:agent_client/services/signing_as_the_identity_that_owns_a_machine.dart';
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
  test('a request to the machine carries a signature made for it', () async {
    final w = _Watcher();
    final c = SigningAsTheIdentityThatOwnsAMachine(
      machineOrigin: _machine,
      localCoreOrigin: _core,
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
  });

  test('nothing else is signed, however similar the name', () async {
    final w = _Watcher();
    final c = SigningAsTheIdentityThatOwnsAMachine(
      machineOrigin: _machine,
      localCoreOrigin: _core,
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

  test('a machine this device does not own goes unsigned rather than wrong',
      () async {
    final w = _Watcher();
    final c = SigningAsTheIdentityThatOwnsAMachine(
      machineOrigin: _machine,
      localCoreOrigin: _core,
      ownerAid: _owner(null),
      inner: w.client,
    );

    await c.get(Uri.parse('$_machine/api/identity'));

    // It must not reach for the local core's own answer, and must not sign as
    // anything else. The machine refuses, which says more about what to do next
    // than a signature from the wrong identity ever could.
    expect(w.signAsked, isNull);
    expect(w.requests.single.headers.containsKey('X-IA-Owner-Sig'), isFalse);
  });

  test('a core that will not sign leaves the request unsigned', () async {
    final w = _Watcher()..signature = null;
    final c = SigningAsTheIdentityThatOwnsAMachine(
      machineOrigin: _machine,
      localCoreOrigin: _core,
      ownerAid: _owner('EMINTEDHERE'),
      inner: w.client,
    );

    await c.get(Uri.parse('$_machine/api/identity'));

    expect(w.signAsked, isNotNull);
    expect(w.requests.last.headers.containsKey('X-IA-Owner-Sig'), isFalse);
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
        localCoreOrigin: _core,
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
        localCoreOrigin: _core,
        using: listing([
          {'url': _machine, 'owner_aid': ''},
        ]),
      );
      expect(await read(), isNull);
    });

    test('a machine this device does not own is null', () async {
      final read = theIdentityThatAdopted(
        _machine,
        localCoreOrigin: _core,
        using: listing(const []),
      );
      expect(await read(), isNull);
    });
  });
}
