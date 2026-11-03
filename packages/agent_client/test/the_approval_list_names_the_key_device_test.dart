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
}
