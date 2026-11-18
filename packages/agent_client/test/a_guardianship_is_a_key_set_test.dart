import 'package:agent_client/services/core_service.dart';
import 'package:test/test.dart';

/// A guardianship the core describes is the dependent's own identifier and the
/// keys in its key set. It carries no identifier of a guardian.
void main() {
  test('a guardianship reads its key set and keeps no guardian identifier', () {
    final g = GuardianshipResponse.fromJson({
      'id': 'g1',
      'type': 'minor_child',
      'dependent_aid': 'EDep',
      'dependent_name': 'Sam',
      'status': 'active',
      'multisig_participants': [
        {'public_key': 'DkeyOne', 'role': 'guardian'},
        {'public_key': 'DkeyTwo', 'role': 'co_guardian'},
      ],
      'multisig_threshold': 2,
    });
    expect(g.dependentAid, 'EDep');
    expect(g.multisigParticipants.map((p) => p.publicKey), ['DkeyOne', 'DkeyTwo']);
    expect(g.multisigParticipants[1].role, 'co_guardian');
    expect(g.multisigThreshold, 2);
    expect(g.isActive, isTrue);
  });

  test('a guardianship with no key set yet reads as an empty one', () {
    final g = GuardianshipResponse.fromJson({'id': 'g2'});
    expect(g.multisigParticipants, isEmpty);
  });

  test('a participant is sent as a public key and a role, nothing else', () {
    expect(MultisigParticipantResponse(publicKey: 'Dk', role: 'court').toJson(),
        {'public_key': 'Dk', 'role': 'court'});
  });
}
