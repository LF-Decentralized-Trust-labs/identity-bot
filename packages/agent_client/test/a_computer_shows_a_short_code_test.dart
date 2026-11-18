import 'dart:convert';

import 'package:agent_client/services/approving_a_machine_to_act_for_you.dart';
import 'package:agent_client/services/asking_to_act_for_an_identity.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

/// A computer asks to act for an identity by a short pointer to its signed
/// offer, left at the Identity Agent it asks (ADR-041 Amendment 1), and the
/// owner's approval of the scan is never itself the grant.
void main() {
  const localCore = 'http://127.0.0.1:5050';
  const agent = 'https://box.example.test';
  const token = 'AAAAAAAAAAAAAAAAAAAAAA';

  Map<String, dynamic> signedOffer() => {
        'aid': 'BTHISMACHINE',
        'public_key': 'DTHISMACHINE',
        'protected_by': 'Apple Secure Enclave',
        'agent_origin': agent,
        'timestamp': '2026-11-18T12:00:00Z',
        'signature': '0BSIGNATURE',
      };

  group('the code a computer shows', () {
    test('is signed beside it, left at the Identity Agent, and is short',
        () async {
      final asked = <http.Request>[];
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((req) async {
          asked.add(req);
          if (req.url.toString() == '$localCore/api/controller/offer') {
            return http.Response(jsonEncode(signedOffer()), 200);
          }
          return http.Response(
              jsonEncode({
                'token': token,
                'url': '$agent/i/$token',
                'expires_at': '2026-11-18T12:05:00Z',
              }),
              200);
        }),
      );

      final code =
          await asking.aShortCodeFor('$agent/', orgName: 'Acme', label: 'Study');

      expect(asked.map((r) => r.url.toString()).toList(), [
        '$localCore/api/controller/offer',
        '$agent/api/controller/requests',
      ]);
      // What is left is the signed offer, with the two display strings.
      final left = jsonDecode(asked[1].body) as Map<String, dynamic>;
      expect(left['signature'], '0BSIGNATURE');
      expect(left['agent_origin'], agent);
      expect(left['label'], 'Study');
      expect(left['org_name'], 'Acme');
      // Unsigned by this machine: it has no standing there yet.
      expect(asked[1].headers.keys.where((k) => k.toLowerCase().startsWith('signature')),
          isEmpty);

      expect(code!.url, '$agent/i/$token');
      expect(code.url.length, lessThan(60));
      expect(code.expiresAt, DateTime.utc(2026, 11, 18, 12, 5));
      expect(code.hasExpired(DateTime.utc(2026, 11, 18, 12, 4)), isFalse);
      expect(code.hasExpired(DateTime.utc(2026, 11, 18, 12, 5)), isTrue);
    });

    test('a pointer to anywhere but the Identity Agent asked is refused',
        () async {
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((req) async {
          if (req.url.path == '/api/controller/offer') {
            return http.Response(jsonEncode(signedOffer()), 200);
          }
          return http.Response(
              jsonEncode({
                'token': token,
                'url': 'https://elsewhere.example/i/$token',
                'expires_at': '2026-11-18T12:05:00Z',
              }),
              200);
        }),
      );
      expect(asking.aShortCodeFor(agent),
          throwsA(isA<ControllerRequestRefused>()));
    });

    test('too many requests is said in words somebody can act on', () async {
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((req) async {
          if (req.url.path == '/api/controller/offer') {
            return http.Response(jsonEncode(signedOffer()), 200);
          }
          return http.Response('{}', 429);
        }),
      );
      expect(
          asking.aShortCodeFor(agent),
          throwsA(isA<ControllerRequestRefused>().having(
              (e) => e.reason, 'reason', contains('wait a minute'))));
    });

    test('is null on hardware that cannot act for an identity', () async {
      final asking = AskingToActForAnIdentity(
        localCoreOrigin: localCore,
        client: MockClient((_) async => http.Response('no enclave', 501)),
      );
      expect(await asking.aShortCodeFor(agent), isNull);
    });
  });

  group('the owner approving the scan', () {
    test('names the machine to grant, and grants nothing itself', () {
      final machine = AMachineAsking.fromApprovedScan({
        'ok': true,
        'approved': true,
        'granted': false,
        'machine': {
          'controller_aid': 'BTHISMACHINE',
          'public_key': 'DTHISMACHINE',
          'protected_by': 'Apple Secure Enclave',
          'agent_origin': agent,
          'label': 'Study',
        },
      });
      expect(machine!.aid, 'BTHISMACHINE');
      expect(machine.agentOrigin, agent);
      expect(machine.suggestedLabel, 'Study');
    });

    test('a declined or malformed answer names no machine', () {
      expect(AMachineAsking.fromApprovedScan({'ok': true, 'approved': false}),
          isNull);
      expect(
          AMachineAsking.fromApprovedScan({
            'approved': true,
            'machine': {'controller_aid': 'B'}
          }),
          isNull);
    });
  });
}
