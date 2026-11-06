import 'package:agent_client/services/recovery_service.dart';
import 'package:test/test.dart';

// The core reports contact_logs_kept when a recovery is activated; the client
// must carry it so a restore screen can tell the owner some contact logs were
// not put back. Fails when RecoverySession.fromJson drops the field.
void main() {
  test('a recovery session carries how many contact logs were kept', () {
    final s = RecoverySession.fromJson({
      'id': 'r1',
      'state': 'activated',
      'contact_logs_kept': 2,
    });
    expect(s.contactLogsKept, 2);
  });

  test('a session that says nothing kept none', () {
    expect(RecoverySession.fromJson({'id': 'r1'}).contactLogsKept, 0);
  });
}
