import 'dart:convert';

import 'package:agent_client/services/approving_a_machine_to_act_for_you.dart';
import 'package:http/http.dart' as http;
import 'package:test/test.dart';

const _agent = 'https://agent.example.test';

class _Recorder extends http.BaseClient {
  final List<http.Request> sent = [];
  String body = '{"controllers":[]}';
  int status = 200;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    sent.add(request as http.Request);
    return http.StreamedResponse(Stream.value(utf8.encode(body)), status);
  }
}

void main() {
  _anIdentityIsNotAComputer();

  test('what a machine offers is read from the code it showed', () {
    final m = ApprovingAMachineToActForYou.readWhatItOffers(jsonEncode({
      // The same 32 bytes twice: B says the identifier IS a non-transferable
      // key, D says this is a verification key. Never equal as text.
      'aid': 'BTheLaptop',
      'public_key': 'DTheLaptop',
      'protected_by': 'Apple Secure Enclave',
      'label': 'MacBook',
    }));
    expect(m.aid, 'BTheLaptop');
    expect(m.publicKey, 'DTheLaptop');
    expect(m.protectedBy, 'Apple Secure Enclave');
    // A suggestion only. A machine that could name itself in somebody's device
    // list could name itself something reassuring.
    expect(m.suggestedLabel, 'MacBook');
  });

  test('a code that names no key is refused, because a grant needs both', () {
    expect(() => ApprovingAMachineToActForYou.readWhatItOffers('{"aid":"BOnly"}'),
        throwsA(isA<FormatException>()));
  });

  test('keeping it and borrowing it send different grades', () async {
    final rec = _Recorder();
    final approving =
        ApprovingAMachineToActForYou(agentOrigin: _agent, client: rec);
    const machine =
        AMachineAsking(aid: 'BTheLaptop', publicKey: 'DTheLaptopKey');

    await approving.approve(
        machine: machine, label: 'the laptop in the study', theyAreKeepingIt: true);
    await approving.approve(
        machine: machine, label: 'a library computer', theyAreKeepingIt: false);

    final first = jsonDecode(rec.sent[0].body) as Map<String, dynamic>;
    final second = jsonDecode(rec.sent[1].body) as Map<String, dynamic>;
    expect(first['grade'], 'enrolled');
    expect(second['grade'], 'scoped');
    expect(first['controller_aid'], 'BTheLaptop');
    expect(first['label'], 'the laptop in the study');
    expect(rec.sent[0].url.toString(), '$_agent/api/controllers');
  });

  test('a machine with no name is refused before anything is sent', () async {
    final rec = _Recorder();
    final approving =
        ApprovingAMachineToActForYou(agentOrigin: _agent, client: rec);
    await expectLater(
      approving.approve(
        machine: const AMachineAsking(aid: 'B', publicKey: 'D'),
        label: '   ',
        theyAreKeepingIt: true,
      ),
      throwsA(isA<ArgumentError>()),
    );
    expect(rec.sent, isEmpty,
        reason: 'an unnamed machine reached the agent, and the owner would not '
            'know which one to remove later');
  });

  test('a refusal from the agent is surfaced, not swallowed', () async {
    final rec = _Recorder()
      ..status = 403
      ..body = '{"error":"not_authorized"}';
    final approving =
        ApprovingAMachineToActForYou(agentOrigin: _agent, client: rec);
    await expectLater(
      approving.approve(
        machine: const AMachineAsking(aid: 'B', publicKey: 'D'),
        label: 'somewhere',
        theyAreKeepingIt: true,
      ),
      throwsA(isA<ApprovalRefused>()),
    );
  });

  test('machines that stopped are still shown, and say why', () async {
    final rec = _Recorder()
      ..body = jsonEncode({
        'controllers': [
          {
            'controller_aid': 'BKept',
            'label': 'the laptop',
            'grade': 'enrolled',
            'live': true,
          },
          {
            'controller_aid': 'BBorrowed',
            'label': 'a library computer',
            'grade': 'scoped',
            'live': false,
            'expires_at': '2026-08-30T10:00:00Z',
            'why_not': 'this authorisation was for a machine somebody borrowed, '
                'and it has expired',
          },
        ]
      });
    final approving =
        ApprovingAMachineToActForYou(agentOrigin: _agent, client: rec);

    final machines = await approving.theMachinesThatMayAct();
    expect(machines, hasLength(2));
    expect(machines[0].theyAreKeepingIt, isTrue);
    expect(machines[1].live, isFalse);
    expect(machines[1].whyNot, contains('expired'));
    expect(machines[1].expiresAt, isNotNull);
  });

  test('revoking names the machine in the path and needs nothing reachable',
      () async {
    final rec = _Recorder()..body = '{"ok":true}';
    final approving =
        ApprovingAMachineToActForYou(agentOrigin: _agent, client: rec);

    await approving.revoke('BTheLaptop');

    expect(rec.sent.single.method, 'DELETE');
    expect(rec.sent.single.url.toString(), '$_agent/api/controllers/BTheLaptop');
  });
}

/// An identity's own discovery record is not a computer asking to act.
///
/// It is exactly the same shape — an identifier and a public key — and it is
/// served to anybody who knows the identifier. Read as a machine, it reached
/// the question "let this computer act for you" naming a PERSON, and the
/// refusal that followed talked about a controller's identifier at somebody who
/// had just scanned somebody else. No authority was ever granted, because the
/// agent refuses a grant whose identifier and key disagree — but the words were
/// wrong, and the words are what the person has.
void _anIdentityIsNotAComputer() {
  test('a discovery record is refused, in words about what it actually is', () {
    // The real shape of what an agent serves at its own OOBI address.
    final theirRecord = jsonEncode({
      'aid': 'EBkHULb-btNlTxGi8Jhao_Y2fBI6Y9yvguWRf29gVPta',
      'public_key': 'DTHEIRSIGNINGKEY',
      'alias': 'somebody',
    });

    expect(
      () => ApprovingAMachineToActForYou.readWhatItOffers(theirRecord),
      throwsA(predicate((e) =>
          '$e'.contains('names an identity rather than a computer'))),
    );
  });

  test('a machine whose identifier and key are different bytes is refused', () {
    // The `B` and the `D` say the same 32 bytes are the identifier and the
    // verification key. Two different values wearing the two codes is a grant
    // the agent would refuse, and refusing it here is where the words are
    // still about what happened.
    expect(
      () => ApprovingAMachineToActForYou.readWhatItOffers(jsonEncode({
        'aid': 'BTHISMACHINE',
        'public_key': 'DSOMEOTHERKEY',
      })),
      throwsA(isA<FormatException>()),
    );
  });

  test('and a machine, whose identifier carries its key, is still read', () {
    final m = ApprovingAMachineToActForYou.readWhatItOffers(jsonEncode({
      'aid': 'BTHISMACHINE',
      'public_key': 'DTHISMACHINE',
    }));
    expect(m.aid, 'BTHISMACHINE');
  });
}
