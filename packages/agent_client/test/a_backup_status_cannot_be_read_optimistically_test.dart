// The client must not be able to turn a bad backup into a reassuring one.
//
// The core reports three separate facts — a backup ran, it was verified, it
// got off this device — precisely because only the last of them means somebody
// is safe. The Dart client parsed the first and dropped the other two, so any
// screen built on it could say "backed up" and could not say anything else.
// That is the same defect as the organisation card that stated a backup 4h ago
// on an agent that had never made one: the words lived where the facts did not.
//
// These tests read status bodies the core genuinely produces and assert the
// client carries the distinction through.

import 'package:agent_client/services/backup_service.dart';
import 'package:test/test.dart';

BackupStatus statusOf(Map<String, dynamic> json) => BackupStatus.fromJson(json);

void main() {
  group('the three facts survive the trip', () {
    test('an agent that has never backed up says so, and is not green', () {
      final s = statusOf({
        'enabled': false,
        'health': 'red',
        'destinations': <dynamic>[],
        'history': <dynamic>[],
        'protection': 'no destination has been added, so nothing leaves this device',
      });

      expect(s.everRan, isFalse);
      expect(s.plainSummary, contains('Not set up yet'));
      expect(s.protection, isNotEmpty);
    });

    test('an archive that never left the device is not called backed up', () {
      // The case that used to read green. A run succeeded, so lastBackupAt is
      // set — and it is sitting on the machine it was made on.
      final s = statusOf({
        'enabled': true,
        'health': 'red',
        'last_backup_at': '2026-08-18T09:00:00Z',
        'last_verified_at': '2026-08-18T09:00:00Z',
        'destinations': <dynamic>[],
        'history': <dynamic>[],
        'protection': 'every archive is on the device that made it',
      });

      expect(s.everRan, isTrue);
      expect(s.lastOffDeviceAt, anyOf(isNull, isEmpty));
      expect(s.plainSummary, 'Backed up, but only onto this device');
    });

    test('an archive nothing has opened is not called checked', () {
      final s = statusOf({
        'enabled': true,
        'health': 'yellow',
        'last_backup_at': '2026-08-18T09:00:00Z',
        'last_off_device_at': '2026-08-18T09:00:00Z',
        'destinations': <dynamic>[],
        'history': <dynamic>[],
      });

      expect(s.lastVerifiedAt, anyOf(isNull, isEmpty));
      expect(s.plainSummary,
          'Backed up off this device, never checked that it opens');
    });

    test('only all three earn the reassuring sentence', () {
      final s = statusOf({
        'enabled': true,
        'health': 'green',
        'last_backup_at': '2026-08-18T09:00:00Z',
        'last_verified_at': '2026-08-18T09:00:00Z',
        'last_off_device_at': '2026-08-18T09:00:00Z',
        'destinations': <dynamic>[],
        'history': <dynamic>[],
      });

      expect(s.plainSummary,
          'Backed up, off this device, and checked that it opens');
    });
  });

  test('a run carries whether it was verified, left, and stands alone', () {
    final s = statusOf({
      'enabled': true,
      'health': 'yellow',
      'destinations': <dynamic>[],
      'history': [
        {
          'id': 'r1',
          'timestamp': '2026-08-18T09:00:00Z',
          'size_bytes': 4096,
          'snapshot_type': 'incremental',
          'success': true,
          'destinations': ['d1'],
          'verified': true,
          'off_device': true,
          'self_sufficient': false,
        }
      ],
    });

    expect(s.history, hasLength(1));
    final run = s.history.single;
    expect(run.verified, isTrue);
    expect(run.offDevice, isTrue);
    // An incremental that reached the far side of the world is still not
    // something anybody can recover from on its own.
    expect(run.selfSufficient, isFalse);
  });

  test('an unknown status body does not become a cheerful default', () {
    // A core that answers with almost nothing must not read as healthy. The
    // dangerous direction of a parsing default is optimism.
    final s = statusOf(<String, dynamic>{});
    expect(s.health, 'red');
    expect(s.everRan, isFalse);
    expect(s.plainSummary, contains('Not set up yet'));
  });
}
