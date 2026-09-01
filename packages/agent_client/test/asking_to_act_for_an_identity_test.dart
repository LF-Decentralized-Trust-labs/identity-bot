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
        client: MockClient((_) async {
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
}
