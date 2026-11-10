import 'dart:convert';

import 'package:agent_client/config/agent_config.dart';
import 'package:agent_client/services/a_controller_offering_itself.dart';
import 'package:agent_client/services/an_agent_proving_itself.dart';
import 'package:agent_client/services/asking_to_act_for_an_identity.dart';
import 'package:agent_client/services/controller_signing_client.dart';
import 'package:agent_client/services/the_owner_at_this_computer.dart';
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

  group('a signed offer this computer can show', () {
    test('is signed by the core beside it, and never by the agent', () async {
      final asked = <http.Request>[];
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((req) async {
          asked.add(req);
          return http.Response(
              jsonEncode({
                'aid': 'BTHISMACHINE',
                'public_key': 'DTHISMACHINE',
                'protected_by': 'Apple Secure Enclave',
                'agent_origin': agent,
                'timestamp': '2026-09-05T00:00:00Z',
                'signature': '0BSIGNATURE',
              }),
              200);
        }),
      );

      final offer = await asking.aSignedOfferFor(agent);

      // Asked of the core beside this app — the only thing that can sign as
      // this machine — and never of the agent. The agent it will act for is
      // the body, because the signature binds the offer to it.
      expect(asked.single.method, 'POST');
      expect(asked.single.url.toString(), '$localCore/api/controller/offer');
      expect(
          (jsonDecode(asked.single.body) as Map)['agent_origin'], agent);
      expect(offer!.aid, 'BTHISMACHINE');
      expect(offer.protectedBy, 'Apple Secure Enclave');
      expect(offer.signature, '0BSIGNATURE');
    });

    test('is null on hardware that cannot act for an identity', () async {
      // 501, not 500: nothing is broken, this computer cannot do it. A screen
      // says so plainly rather than offering a button that will fail.
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((_) async => http.Response('no enclave', 501)),
      );
      expect(await asking.aSignedOfferFor(agent), isNull);
    });

    test('an unsigned response is refused rather than shown', () async {
      // The owner's device accepts no offer without a signature — there is no
      // unsigned path — so failing here beats putting on screen a code that
      // cannot be trusted.
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((_) async => http.Response(
            jsonEncode({'aid': 'BTHIS', 'public_key': 'DTHIS'}), 200)),
      );
      expect(asking.aSignedOfferFor(agent), throwsA(isA<Exception>()));
    });

    test('the scannable link carries every signed field, and round-trips', () {
      const offer = ControllerOffer(
        aid: 'BTHISMACHINE',
        publicKey: 'DTHISMACHINE',
        agentOrigin: agent,
        timestamp: '2026-09-05T00:00:00Z',
        signature: '0BSIGNATURE',
        protectedBy: 'TPM',
      );
      final link = Uri.parse(offer.toScannableLink());
      expect(link.scheme, 'identity-agent');
      expect(link.host, 'controller');
      // Every field the signature covers travels, because the owner's device
      // rebuilds the exact signed string to check it — drop one and it cannot.
      expect(link.queryParameters['aid'], 'BTHISMACHINE');
      expect(link.queryParameters['key'], 'DTHISMACHINE');
      expect(link.queryParameters['agent'], agent);
      expect(link.queryParameters['ts'], '2026-09-05T00:00:00Z');
      expect(link.queryParameters['sig'], '0BSIGNATURE');

      final back = ControllerOffer.parse(offer.toScannableLink());
      expect(back!.signature, '0BSIGNATURE');
      expect(back.agentOrigin, agent);
    });
  });

  group('what the agent says', () {
    test('is null while nobody has approved anything', () async {
      // The ordinary state before somebody picks up their phone. Not an error,
      // and not worth showing anybody as one.
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
          return http.Response('not authorised', 403);
        }),
      );
      expect(await asking.whatTheAgentSays(agent), isNull);
    });

    test('is an error, not "nobody has approved", when this machine cannot sign',
        () async {
      // An unsigned question is refused by the agent exactly like an unapproved
      // one, so the two must not be told apart by the agent's answer.
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((req) async => http.Response('no enclave', 501)),
      );
      await expectLater(
          asking.whatTheAgentSays(agent), throwsA(isA<ThisMachineCouldNotSign>()));
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
        agentAid: 'EMYIDENTITY',
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

      final signRequest = sent.firstWhere(
          (r) => r.url.path == '/api/controller/sign') as http.Request;
      expect((jsonDecode(signRequest.body) as Map)['for'], '',
          reason: 'asking which identity this machine acts for must name '
              'nobody: the core would otherwise name whichever Identity Agent '
              'it was told about before, and this one would refuse it');

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
            agentAid: 'EMYIDENTITY',
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

  /// Which Identity Agent is at an address: proved, not read off the address.
  group('which agent is at an address', () {
    http.Client theCoreSaying(Map<String, dynamic> answer, [int code = 200]) =>
        MockClient((req) async => http.Response(jsonEncode(answer), code));

    test('an agent that proved it holds its keys is named', () async {
      Map<String, dynamic>? asked;
      Uri? at;
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((req) async {
          at = req.url;
          asked = jsonDecode(req.body) as Map<String, dynamic>;
          return http.Response(
              jsonEncode({
                'verified': true,
                'aid': 'EMYIDENTITY',
                'public_key': 'DTHEKEY'
              }),
              200);
        }),
      );
      final proved = await asking.proveWhoIsAt(agent);
      expect(proved.aid, 'EMYIDENTITY');
      // Asked of THIS computer's own core, never of the agent: asking the thing
      // under question to answer for itself proves nothing.
      expect(at.toString(), '$localCore/api/verify/agent-at-address');
      expect(asked!['address'], agent);
    });

    test('is asked as the owner of this computer, because the route is the '
        "owner's", () async {
      // A core that holds the secret, so that it is proven and the secret may
      // be sent to it (nothing is sent to a core that has not proved it).
      LocalOwnerSecret.use('the-secret');
      addTearDown(LocalOwnerSecret.forget);
      expect(
          await LocalOwnerSecret.proveTheCoreAt('http://127.0.0.1:5050',
              using: MockClient((req) async => http.Response(
                  jsonEncode({
                    'proof': LocalOwnerSecret.proof('the-secret',
                        req.url.queryParameters['nonce']!, 5050)
                  }),
                  200))),
          isTrue);
      http.BaseRequest? seen;
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: 'http://127.0.0.1:5050',
        client: MockClient((req) async {
          seen = req;
          return http.Response(
              jsonEncode({
                'verified': true,
                'aid': 'EMYIDENTITY',
                'public_key': 'DK'
              }),
              200);
        }),
      );
      await asking.proveWhoIsAt(agent);
      expect(seen!.headers[LocalOwnerSecret.header], 'the-secret',
          reason: 'the core refused the proof route to a request that did not '
              'carry the owner secret');
    });

    test('something answering that could not prove it is refused', () async {
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: theCoreSaying({
          'verified': false,
          'kind': 'different',
          'why': 'the answer is not signed by the keys it has in force'
        }),
      );
      await expectLater(
          asking.proveWhoIsAt(agent),
          throwsA(isA<AnAgentCouldNotBeProved>()
              .having((e) => e.kind, 'kind', NotProved.somethingElse)));
    });

    test('nothing answering is said as such', () async {
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: theCoreSaying({'verified': false, 'kind': 'no-answer'}),
      );
      await expectLater(
          asking.proveWhoIsAt(agent),
          throwsA(isA<AnAgentCouldNotBeProved>()
              .having((e) => e.kind, 'kind', NotProved.noAnswer)));
    });

    test('a computer that cannot check says so rather than shrugging',
        () async {
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((_) async => http.Response('no engine', 501)),
      );
      await expectLater(
          asking.proveWhoIsAt(agent),
          throwsA(isA<AnAgentCouldNotBeProved>()
              .having((e) => e.kind, 'kind', NotProved.couldNotTell)));
    });

    test('a verified answer for another identifier than the one remembered '
        'is refused', () async {
      await expectLater(
          proveTheAgentAt(agent,
              aid: 'EMYIDENTITY',
              localCoreOrigin: localCore,
              client: theCoreSaying({
                'verified': true,
                'aid': 'ESOMEBODYELSE',
                'public_key': 'DTHEIRKEY'
              })),
          throwsA(isA<AnAgentCouldNotBeProved>()));
    });

    test('a verified answer with no key is not an answer', () async {
      await expectLater(
          proveTheAgentAt(agent,
              localCoreOrigin: localCore,
              client: theCoreSaying({'verified': true, 'aid': 'EMYIDENTITY'})),
          throwsA(isA<AnAgentCouldNotBeProved>()));
    });
  });

  /// A grant is believed only from an agent that has just proved itself.
  group('a grant', () {
    MockClient theAgentGranting({required Map<String, dynamic> proofAnswer}) =>
        MockClient((req) async {
          if (req.url.path == '/api/controller/sign') {
            return http.Response(
                jsonEncode({
                  'controller_aid': 'BTHISMACHINE',
                  'signature': '0BSIG',
                  'timestamp': '2026-09-01T00:00:00Z',
                }),
                200);
          }
          if (req.url.path == '/api/verify/agent-at-address') {
            return http.Response(jsonEncode(proofAnswer), 200);
          }
          return http.Response(
              jsonEncode({
                'aid': 'EMYIDENTITY',
                'label': 'x',
                'your_label': 'the study iMac',
                'your_grade': 'enrolled'
              }),
              200);
        });

    test('is accepted from an agent that proved itself', () async {
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: theAgentGranting(proofAnswer: {
          'verified': true,
          'aid': 'EMYIDENTITY',
          'public_key': 'DK'
        }),
      );
      final told = await asking.waitUntilGranted(agent,
          agentAid: 'EMYIDENTITY', every: const Duration(milliseconds: 1));
      expect(told!.agentAid, 'EMYIDENTITY');
    });

    test('is thrown away when whatever answered cannot prove itself', () async {
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: theAgentGranting(proofAnswer: {
          'verified': false,
          'kind': 'different',
          'why': 'not signed by the keys in force'
        }),
      );
      await expectLater(
          asking.waitUntilGranted(agent,
              agentAid: 'EMYIDENTITY', every: const Duration(milliseconds: 1)),
          throwsA(isA<AnAgentCouldNotBeProved>()));
    });

    MockClient theAgentGrantingWhileTheProofSays(
        List<Map<String, dynamic>> answers, List<Map<String, dynamic>> asked) {
      var n = 0;
      return MockClient((req) async {
        if (req.url.path == '/api/controller/sign') {
          return http.Response(
              jsonEncode({
                'controller_aid': 'BTHISMACHINE',
                'signature': '0BSIG',
                'timestamp': '2026-09-01T00:00:00Z',
              }),
              200);
        }
        if (req.url.path == '/api/verify/agent-at-address') {
          asked.add(jsonDecode(req.body) as Map<String, dynamic>);
          return http.Response(
              jsonEncode(answers[n < answers.length ? n++ : n - 1]), 200);
        }
        return http.Response(
            jsonEncode({'aid': 'EMYIDENTITY', 'your_grade': 'enrolled'}), 200);
      });
    }

    const proved = {'verified': true, 'aid': 'EMYIDENTITY', 'public_key': 'DK'};

    test('is proved against what was proved first, so a rollback in between '
        'is refused', () async {
      final asked = <Map<String, dynamic>>[];
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: theAgentGrantingWhileTheProofSays([proved], asked),
      );
      await asking.waitUntilGranted(agent,
          agentAid: 'EMYIDENTITY',
          knownSequence: 4,
          knownKey: 'DK',
          every: const Duration(milliseconds: 1));
      expect(asked.single['known_sequence'], 4);
      expect(asked.single['known_key'], 'DK');
    });

    test('a passing network blip while proving it is asked again, not '
        'a verdict', () async {
      final asked = <Map<String, dynamic>>[];
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: theAgentGrantingWhileTheProofSays([
          {'verified': false, 'kind': 'no-answer'},
          {'verified': false, 'kind': 'could-not-tell'},
          proved,
        ], asked),
      );
      final told = await asking.waitUntilGranted(agent,
          agentAid: 'EMYIDENTITY',
          every: const Duration(milliseconds: 1),
          blipPause: const Duration(milliseconds: 1));
      expect(told!.agentAid, 'EMYIDENTITY');
      expect(asked, hasLength(3));
    });

    test('a blip that does not pass is thrown as what it is', () async {
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: theAgentGrantingWhileTheProofSays([
          {'verified': false, 'kind': 'no-answer'},
        ], []),
      );
      await expectLater(
          asking.waitUntilGranted(agent,
              agentAid: 'EMYIDENTITY',
              every: const Duration(milliseconds: 1),
              blipPause: const Duration(milliseconds: 1)),
          throwsA(isA<AnAgentCouldNotBeProved>()
              .having((e) => e.kind, 'kind', NotProved.noAnswer)));
    });

    test('a verdict is never asked again', () async {
      final asked = <Map<String, dynamic>>[];
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: theAgentGrantingWhileTheProofSays([
          {'verified': false, 'kind': 'different', 'why': 'older history'},
          proved,
        ], asked),
      );
      await expectLater(
          asking.waitUntilGranted(agent,
              agentAid: 'EMYIDENTITY',
              every: const Duration(milliseconds: 1),
              blipPause: const Duration(milliseconds: 1)),
          throwsA(isA<AnAgentCouldNotBeProved>()
              .having((e) => e.kind, 'kind', NotProved.somethingElse)));
      expect(asked, hasLength(1));
    });

    test('naming another identifier than the one proved is refused', () async {
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((req) async {
          if (req.url.path == '/api/controller/sign') {
            return http.Response(
                jsonEncode({
                  'controller_aid': 'B',
                  'signature': '0BSIG',
                  'timestamp': '2026-09-01T00:00:00Z'
                }),
                200);
          }
          if (req.url.path == '/api/verify/agent-at-address') {
            return http.Response(
                jsonEncode({
                  'verified': true,
                  'aid': 'EMYIDENTITY',
                  'public_key': 'DK'
                }),
                200);
          }
          return http.Response(
              jsonEncode({'aid': 'EANOTHER', 'your_grade': 'enrolled'}), 200);
        }),
      );
      await expectLater(
          asking.waitUntilGranted(agent,
              agentAid: 'EMYIDENTITY', every: const Duration(milliseconds: 1)),
          throwsA(isA<AnAgentCouldNotBeProved>()));
    });
  });

  test('the scannable link names the Identity Agent being asked', () {
    // Without it the device holding the key posts the grant to its own core,
    // which on the ordinary arrangement is not the agent — and the computer
    // waits for a grant written somewhere else.
    const offer = ControllerOffer(
      aid: 'BTHIS',
      publicKey: 'DTHIS',
      agentOrigin: 'https://box.example.test',
      timestamp: '2026-09-05T00:00:00Z',
      signature: '0BSIG',
    );
    final link = Uri.parse(offer.toScannableLink());
    expect(link.queryParameters['agent'], 'https://box.example.test');
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
            agentAid: 'EMYIDENTITY',
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
