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
