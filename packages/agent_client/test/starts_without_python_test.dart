import 'package:test/test.dart';
import 'package:agent_client/services/backend_process_service.dart';

/// keri-go is the only KERI engine, so the desktop launcher needs no Python.
///
/// The launcher once demanded Python before it looked at anything else, and the
/// moment the Python driver stopped shipping that turned into a refusal to
/// start: it found a system python, could not import flask or keri, and tried
/// to pip install them from inside a signed application bundle. What a person
/// saw was an app that opened and vanished.
///
/// That driver is gone — the backend runs keri-go in-process — so nothing in the
/// launcher looks for Python at all. These lock that in: the launcher's only
/// hard input is the backend binary, and an entity type set on it survives.
void main() {
  test('startup fails for a missing backend binary, never for missing Python', () async {
    // The test runner is not the packaged app, so no backend binary sits beside
    // it and startup must fail. The point is WHICH failure: the missing binary,
    // never a hunt for Python, which the launcher no longer performs.
    final started = await BackendProcessService.instance.start();
    expect(started, isFalse);

    final err = (BackendProcessService.instance.startupError ?? '').toLowerCase();
    expect(err, contains('backend binary'),
        reason: 'the only hard requirement is the backend binary');
    expect(err, isNot(contains('python')),
        reason: 'Python is never required, so it can never be the reason to fail');
  });

  test('the entity type an app declares survives being set', () {
    // Not about Python, but it travels in the same environment block and a
    // rearrangement of that block is exactly what could drop it.
    BackendProcessService.entityType = 'organization';
    expect(BackendProcessService.entityType, 'organization');
    BackendProcessService.entityType = null;
  });
}
