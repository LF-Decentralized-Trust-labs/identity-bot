import 'package:agent_client/services/core_service.dart';
import 'package:test/test.dart';

Map<String, dynamic> _contact([String? entityType]) => {
      'aid': 'EAid',
      'alias': 'x',
      'verified': true,
      if (entityType != null) 'entity_type': entityType,
    };

void main() {
  test('a contact that published itself as an organisation is one', () {
    final c = ContactResponse.fromJson(_contact('organization'));
    expect(c.entityType, 'organization');
    expect(c.isOrganisation, isTrue);
  });

  test('a person is not an organisation', () {
    expect(ContactResponse.fromJson(_contact('individual')).isOrganisation,
        isFalse);
  });

  test('a contact that never said is not taken to be an organisation', () {
    final c = ContactResponse.fromJson(_contact());
    expect(c.entityType, isEmpty);
    expect(c.isOrganisation, isFalse);
  });
}
