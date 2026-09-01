import 'dart:convert';

import 'package:agent_client/config/agent_config.dart';
import 'package:agent_client/services/asking_to_act_for_an_identity.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

/// The machine's own half of asking to act for an identity.
///
/// Two questions of two different places, and the tests are mostly about
/// keeping them apart: what this computer OFFERS only the core beside it can
/// answer, and what it has BEEN GRANTED only the agent knows.
void main() {
  tearDown(() => AgentConfig.agentOrigin = '');

  const localCore = 'http://127.0.0.1:5050';
  const agent = 'https://box.example.test';

  group('what this computer offers', () {
    test('is asked of the core beside it, and never of the agent', () async {
      final asked = <Uri>[];
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((req) async {
          asked.add(req.url);
          return http.Response(
              jsonEncode({
                'aid': 'BTHISMACHINE',
                'public_key': 'DTHISMACHINE',
                'protected_by': 'Apple Secure Enclave',
              }),
              200);
        }),
      );

      final offering = await asking.whatThisComputerOffers();

      expect(asked.single.toString(),
          '$localCore/api/controller/this-machine');
      expect(offering!.aid, 'BTHISMACHINE');
      expect(offering.protectedBy, 'Apple Secure Enclave');
    });

    test('is null on hardware that cannot act for an identity', () async {
      // 501, not 500: nothing is broken, this computer cannot do it. A screen
      // says so plainly rather than offering a button that will fail.
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((_) async => http.Response('no enclave', 501)),
      );
      expect(await asking.whatThisComputerOffers(), isNull);
    });

    test('a machine naming no key is refused rather than shown', () async {
      // An identifier with no key is nothing anybody could authorise, and the
      // agent would refuse the grant. Better to fail here than to put a code on
      // screen that cannot work.
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient(
            (_) async => http.Response(jsonEncode({'aid': 'BTHIS'}), 200)),
      );
      expect(asking.whatThisComputerOffers(), throwsA(isA<Exception>()));
    });

    test('what is scanned carries both the identifier and the key', () async {
      const offering = AMachineOffering(
          aid: 'BTHISMACHINE', publicKey: 'DTHISMACHINE', protectedBy: 'TPM');
      final decoded = jsonDecode(offering.toBeScanned) as Map<String, dynamic>;
      // Both, though they are one value in different clothes: the agent refuses
      // a grant whose identifier and key disagree, so it can check rather than
      // trust whoever expanded one into the other.
      expect(decoded['aid'], 'BTHISMACHINE');
      expect(decoded['public_key'], 'DTHISMACHINE');
      expect(decoded['protected_by'], 'TPM');
    });
  });

  group('what the agent says', () {
    test('is null while nobody has approved anything', () async {
      // The ordinary state before somebody picks up their phone. Not an error,
      // and not worth showing anybody as one.
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((_) async => http.Response('not authorised', 403)),
      );
      expect(await asking.whatTheAgentSays(agent), isNull);
    });

    test('names the identity, and what this machine was approved as', () async {
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((req) async {
          if (req.url.path == '/api/controller/sign') {
            return http.Response(
                jsonEncode({
                  'controller_aid': 'BTHISMACHINE',
                  'signature': '0BSIG',
                  'timestamp': '2026-09-01T00:00:00Z',
                }),
                200);
          }
          return http.Response(
              jsonEncode({
                'aid': 'EMYIDENTITY',
                'label': 'my black box',
                'your_label': 'the study iMac',
                'your_grade': 'enrolled',
              }),
              200);
        }),
      );

      final told = await asking.whatTheAgentSays(agent);
      expect(told!.agentAid, 'EMYIDENTITY');
      expect(told.yourLabel, 'the study iMac');
      // What the person was actually asked: is this one you keep, or one you
      // are using for now.
      expect(told.theyAreKeepingIt, isTrue);
      expect(told.yourAuthorisationEnds, isNull);
    });

    test('running out is nothing yet, not a failure', () async {
      var asked = 0;
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((req) async {
          if (req.url.path == '/api/controller/sign') {
            return http.Response(
                jsonEncode({
                  'controller_aid': 'BTHISMACHINE',
                  'signature': '0BSIG',
                  'timestamp': '2026-09-01T00:00:00Z',
                }),
                200);
          }
          asked++;
          return http.Response('not authorised', 403);
        }),
      );

      final told = await asking.waitUntilGranted(
        agent,
        every: const Duration(milliseconds: 1),
        until: const Duration(milliseconds: 20),
      );
      // The usual reason is that nobody has picked up their phone, so this is
      // "nothing yet" rather than something that went wrong.
      expect(told, isNull);
      expect(asked, greaterThan(0));
    });
  });

  /// The poll is signed AS THIS MACHINE, or the ceremony cannot finish.
  ///
  /// This is circular if it goes through the transport that decides for itself:
  /// that one picks the controller client only once the app already IS a
  /// controller, which is the state this call exists to reach. It would send the
  /// request unsigned, the Identity Agent would read it as not coming from a
  /// controller and refuse, and this method reports a refusal as "nobody has
  /// approved you yet" — so somebody could approve it on their phone and the
  /// computer would wait for ever, saying nothing was approved.
  ///
  /// Asserted on the headers that actually leave, because asserting the URL is
  /// what missed it: the request went to the right place carrying nothing.
  group('the poll proves who is asking', () {
    test('it asks this machine to sign, and sends what came back', () async {
      final sent = <http.BaseRequest>[];
      var askedToSign = false;

      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((req) async {
          sent.add(req);
          if (req.url.path == '/api/controller/sign') {
            askedToSign = true;
            expect(req.url.toString(),
                '$localCore/api/controller/sign',
                reason: 'the key is in THIS machine, so the signing is asked of '
                    'the core beside it and never of the Identity Agent');
            return http.Response(
                jsonEncode({
                  'controller_aid': 'BTHISMACHINE',
                  'signature': '0BSIG',
                  'timestamp': '2026-09-01T00:00:00Z',
                }),
                200);
          }
          return http.Response(jsonEncode({'aid': 'EMYIDENTITY'}), 200);
        }),
      );

      await asking.whatTheAgentSays(agent);

      expect(askedToSign, isTrue,
          reason: 'nothing asked this machine to sign, so the request went to '
              'the Identity Agent unsigned and would be refused for ever');

      final toTheAgent =
          sent.firstWhere((r) => r.url.toString().startsWith(agent));
      expect(toTheAgent.headers['X-IA-Controller-AID'], 'BTHISMACHINE');
      expect(toTheAgent.headers['X-IA-Controller-Sig'], '0BSIG');
      // Echoed from the core rather than formatted again: the moment is inside
      // the signature.
      expect(toTheAgent.headers['X-IA-Controller-Timestamp'],
          '2026-09-01T00:00:00Z');
    });

    test('it never asks whether this device adopted the agent', () async {
      // The fingerprint of the wrong client. Reaching for the adopted-machines
      // list means the transport chose "a machine this device owns" — which is
      // what happens when the choice is made from whether this app is already a
      // controller, and it is not one yet.
      final asked = <String>[];
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((req) async {
          asked.add(req.url.path);
          if (req.url.path == '/api/controller/sign') {
            return http.Response(
                jsonEncode({
                  'controller_aid': 'BTHISMACHINE',
                  'signature': '0BSIG',
                  'timestamp': '2026-09-01T00:00:00Z',
                }),
                200);
          }
          return http.Response(jsonEncode({'aid': 'EMYIDENTITY'}), 200);
        }),
      );

      await asking.whatTheAgentSays(agent);
      expect(asked, isNot(contains('/api/agents')));
    });
  });

  /// A machine that cannot sign is told so, rather than left waiting.
  ///
  /// The signing client sends unsigned when the core will not sign — by design,
  /// documented, and correct for its own purposes. From here that is
  /// indistinguishable from nobody having approved anything, so without this a
  /// machine whose enclave is locked waits the full ten minutes and then
  /// reports that nothing was approved, however many times somebody approved
  /// it. The person would go and check their phone, find they HAD approved it,
  /// and have nowhere to go from there.
  group('a machine that cannot sign', () {
    test('is told so before it waits on anything', () async {
      var reachedTheAgent = false;
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((req) async {
          if (req.url.path == '/api/controller/sign') {
            return http.Response('this computer has no usable enclave', 501);
          }
          reachedTheAgent = true;
          return http.Response('not authorised', 403);
        }),
      );

      await expectLater(
        asking.waitUntilGranted(agent,
            every: const Duration(milliseconds: 1),
            until: const Duration(milliseconds: 20)),
        throwsA(isA<Exception>()),
      );
      expect(reachedTheAgent, isFalse,
          reason: 'it waited on an Identity Agent that could never have '
              'recognised it, which reads to the person as nobody approving');
    });

    test('and the reason it gives is the one somebody can act on', () async {
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((_) async =>
            http.Response('the enclave is locked', 501)),
      );
      await expectLater(
        asking.confirmThisMachineCanSign(),
        throwsA(predicate((e) => '$e'.contains('the enclave is locked'))),
      );
    });
  });

  /// Which Identity Agent is at an address, and whether one is.
  ///
  /// Asked of the two routes a real agent answers to a stranger. Reaching for
  /// an owner-only route and reading its refusal as success accepts far too
  /// much: anything behind an access proxy, any server with a deny rule, any
  /// JSON endpoint returning an object without the field, and any OTHER
  /// person's agent all refuse identically — and the person then spends ten
  /// silent minutes waiting on a machine that was never going to answer.
  group('which agent is at an address', () {
    http.Client answering(Map<String, int> codes, {String body = '{}'}) =>
        MockClient((req) async =>
            http.Response(body, codes[req.url.path] ?? 404));

    test('a real Identity Agent is recognised by how it answers', () async {
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((req) async {
          if (req.url.path == '/api/health') {
            return http.Response(
                jsonEncode({'status': 'active', 'agent': 'keri-go'}), 200);
          }
          return http.Response('no', 404);
        }),
      );
      await asking.confirmAnAgentIsAt(agent);
    });

    test('a server that merely refuses is not an Identity Agent', () async {
      // The whole class an owner-only check accepted: an access proxy, a deny
      // rule, a relay that refuses unknown paths, somebody else's agent.
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: answering({'/api/health': 403}),
      );
      expect(asking.confirmAnAgentIsAt(agent), throwsA(isA<Exception>()));
    });

    test('a JSON endpoint answering 200 is not an Identity Agent', () async {
      // The status alone is not enough: a great many things answer 200 at a
      // path they do not know. Far fewer describe themselves this way.
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: answering({'/api/health': 200}, body: '{"status":"ok"}'),
      );
      expect(asking.confirmAnAgentIsAt(agent), throwsA(isA<Exception>()));
    });

    test('an HTML page is refused rather than parsed', () async {
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: answering({'/api/health': 200}, body: '<html>hello</html>'),
      );
      expect(asking.confirmAnAgentIsAt(agent), throwsA(isA<Exception>()));
    });
  });

  test('what is scanned names the Identity Agent being asked', () {
    // Without it the device holding the key posts the grant to its own core,
    // which on the ordinary arrangement is not the agent — and the computer
    // waits for a grant written somewhere else.
    const offering = AMachineOffering(
        aid: 'BTHIS', publicKey: 'BTHIS', agentOrigin: 'https://box.example.test');
    final decoded = jsonDecode(offering.toBeScanned) as Map<String, dynamic>;
    expect(decoded['agent_origin'], 'https://box.example.test');
  });

  test('a wait stops when the screen that started it goes away', () async {
    // It used to go on asking every two seconds for the rest of its ten
    // minutes, against a client already closed, long after anybody was
    // watching. Nothing broke; it kept a machine busy for nobody.
    var asked = 0;
    final asking = AskingToActForAnIdentity(
      localCoreOrigin: localCore,
      client: MockClient((req) async {
        if (req.url.path == '/api/controller/sign') {
          return http.Response(
              jsonEncode({
                'controller_aid': 'B1',
                'signature': '0BSIG',
                'timestamp': '2026-09-01T00:00:00Z',
              }),
              200);
        }
        asked++;
        return http.Response('not authorised', 403);
      }),
    );

    final waiting = asking.waitUntilGranted(agent,
        every: const Duration(milliseconds: 5),
        until: const Duration(seconds: 30));

    await Future<void>.delayed(const Duration(milliseconds: 30));
    asking.dispose();
    final afterDispose = asked;

    // It returns rather than running out the clock.
    expect(await waiting.timeout(const Duration(seconds: 2)), isNull);
    await Future<void>.delayed(const Duration(milliseconds: 40));
    expect(asked, lessThanOrEqualTo(afterDispose + 1),
        reason: 'it went on asking after being disposed');
  });
}
