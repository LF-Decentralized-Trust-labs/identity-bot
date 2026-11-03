import 'dart:convert';

import 'package:agent_client/models/awaiting_approval.dart';
import 'package:test/test.dart';

void main() {
  test('a machine waiting for the key device carries that device\'s name', () {
    final list = AwaitingApproval.fromJson(jsonDecode('''
      {"machines":[{"controller_aid":"BLaptop","public_key":"DKey","label":"study laptop",
        "grade":"enrolled","awaiting":"the device that holds the identity's key",
        "key_device_name":"Rob's iPhone"}],
       "agents":[{"asset_id":"a1","name":"Helper","agent_aid":"EHelper",
        "capabilities":["read"],"awaiting":"the device that holds the identity's key",
        "key_device_name":"Rob's iPhone"}]}''') as Map<String, dynamic>);
    expect(list.machines.single.keyDeviceName, "Rob's iPhone");
    expect(list.machines.single.label, 'study laptop');
    expect(list.agents.single.keyDeviceName, "Rob's iPhone");
    expect(list.agents.single.capabilities, ['read']);
  });

  test('no name is null, never made up, and an older core still reads', () {
    final list = AwaitingApproval.fromJson(jsonDecode('''
      {"machines":[{"controller_aid":"B1","awaiting":"the owner's approval"},
                   {"controller_aid":"B2","awaiting":"x","key_device_name":"  "}]}''')
        as Map<String, dynamic>);
    expect(list.machines.map((m) => m.keyDeviceName), [null, null]);
    expect(list.agents, isEmpty);
    expect(AwaitingApproval.fromJson({}).isEmpty, isTrue);
  });

  test('a machine carries every field the route sends', () {
    final m = AwaitingApproval.fromJson(jsonDecode('''
      {"machines":[{"controller_aid":"B1","public_key":"DK","label":"l","grade":"enrolled",
        "granted_at":"2026-11-03T20:21:20.5Z","live":true,"expires_at":"2026-12-01T00:00:00Z",
        "signer":"EOWNER","credential":"pending on the device that holds the identity's key",
        "awaiting":"the device that holds the identity's key refused it: ask again",
        "waiting_for_key_device":true,"key_device_name":"Rob's iPhone"},
        {"controller_aid":"B2","live":false,"why_not":"expired"}],
       "agents":[{"asset_id":"a","name":"n","agent_aid":"E","resource_constraints":{"x":1},
        "awaiting":"y","waiting_for_key_device":true}],
       "grants_withdrawing":[{"credential":"S","holder":"B1","withdrawal":"refused"}],
       "key_log_unsigned_events":[1,3],"key_log_detail":"fix it",
       "key_log_anchors_not_held":[{"interaction":"I","anchors":[]}],
       "key_log_anchors_not_held_unreadable":"bad"}''') as Map<String, dynamic>);
    final a = m.machines.first;
    expect(a.grantedAt, DateTime.utc(2026, 11, 3, 20, 21, 20, 500));
    expect(a.live, isTrue);
    expect(a.expiresAt, DateTime.utc(2026, 12, 1));
    expect(a.signer, 'EOWNER');
    expect(a.credential, startsWith('pending'));
    expect(a.waitingForKeyDevice, isTrue);
    expect(m.machines.last.whyNot, 'expired');
    expect(m.machines.last.grantedAt, isNull);
    expect(m.agents.single.waitingForKeyDevice, isTrue);
    expect(m.agents.single.resourceConstraints, {'x': 1});
    expect(m.grantsWithdrawing.single['withdrawal'], 'refused');
    expect(m.keyLogUnsignedEvents, [1, 3]);
    expect(m.keyLogDetail, 'fix it');
    expect(m.keyLogAnchorsNotHeld.single['interaction'], 'I');
    expect(m.keyLogAnchorsNotHeldUnreadable, 'bad');
    expect(m.isEmpty, isFalse);
  });
}
