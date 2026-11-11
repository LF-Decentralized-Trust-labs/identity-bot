import 'package:agent_client/services/backend_process_service.dart';
import 'package:test/test.dart';

/// Stopping a core signals the process that holds its port, never a process a
/// stale pid file happens to name.
void main() {
  final decide = BackendProcessService.decideWhichProcessEndsTheCore;

  test('the process holding the port is the one', () {
    expect(decide(holdingThePort: '4242').pid, '4242');
    expect(decide(holdingThePort: '4242', fromPidFile: '4242').pid, '4242');
  });

  test('a pid file that disagrees with the port holder signals nothing', () {
    final d = decide(holdingThePort: '4242', fromPidFile: '17');
    expect(d.pid, isNull);
    expect(d.refusal, contains('17'));
  });

  test('a pid file alone is not enough to signal a process', () {
    expect(decide(fromPidFile: '17').pid, isNull);
    expect(decide(fromPidFile: '17').refusal, isNotNull);
    expect(decide().pid, isNull);
  });

  test('an unreadable pid file does not stop the port holder being ended', () {
    expect(decide(holdingThePort: '4242', fromPidFile: 'junk').pid, '4242');
  });
}
