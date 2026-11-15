import 'package:agent_client/services/core_service.dart';
import 'package:test/test.dart';

// The Identity Agent writes when each invited owner's code was last used to read
// the ceremony, and when the rotation now being signed was prepared. The
// organisation's screen shows them; a time that was never set is left out of the
// answer and must read as none, not as a time.

void main() {
  test('a look and the time the rotation was prepared are read', () {
    final c = OwnerCeremony.fromJson({
      'id': 'c1',
      'status': 'signing',
      'stage': 'rot1',
      'stage_since': '2026-11-15T09:00:00Z',
      'invited': [
        {'name': 'Ada', 'last_seen_at': '2026-11-15T10:42:00Z'},
        {'name': 'Grace'},
      ],
    });
    expect(c.stageSince, DateTime.utc(2026, 11, 15, 9));
    expect(c.invited[0].lastSeenAt, DateTime.utc(2026, 11, 15, 10, 42));
    expect(c.invited[1].lastSeenAt, isNull);
  });

  test('a time that is missing, empty or not a time reads as none', () {
    for (final v in [null, '', 'soon', 5]) {
      final c = OwnerCeremony.fromJson({
        'id': 'c1',
        'stage_since': v,
        'invited': [
          {'name': 'Ada', 'last_seen_at': v},
        ],
      });
      expect(c.stageSince, isNull, reason: '$v');
      expect(c.invited.single.lastSeenAt, isNull, reason: '$v');
    }
  });
}
