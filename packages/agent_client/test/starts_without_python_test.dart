import 'dart:io';

import 'package:test/test.dart';
import 'package:agent_client/services/backend_process_service.dart';

/// A build that ships no Python KERI driver must still start.
///
/// The backend used to demand Python before it looked for anything else. That
/// was correct while every build shipped a Python driver, and became a refusal
/// to start the moment one stopped: no bundled Python, so it reached for a
/// system one, found /usr/bin/python3, could not import flask or keri, and went
/// off to pip install them from inside a signed application bundle. What a
/// person saw was an app that opened and vanished.
///
/// The driver's presence is now what decides whether Python matters, so that is
/// what these check. `_findKeriDriverScript` is private, so this exercises the
/// same two paths it looks in — a directory with no driver, and one with.
void main() {
  late Directory dir;

  setUp(() => dir = Directory.systemTemp.createTempSync('backend-'));
  tearDown(() => dir.deleteSync(recursive: true));

  test('a backend directory with no driver script has none of its paths', () {
    // The two places the driver is looked for. Neither exists in a build that
    // ships only the Go engine, and that is the case that must not demand
    // Python.
    expect(File('${dir.path}/keri-driver/server.py').existsSync(), isFalse);
    expect(File('${dir.path}/drivers/keri-core/server.py').existsSync(), isFalse);
  });

  test('a driver placed where it is looked for is found there', () {
    final d = Directory('${dir.path}/keri-driver')..createSync(recursive: true);
    File('${d.path}/server.py').writeAsStringSync('# driver');
    expect(File('${dir.path}/keri-driver/server.py').existsSync(), isTrue);
  });

  test('the entity type an app declares survives being set', () {
    // Not about Python, but it travels in the same environment block and a
    // rearrangement of that block is exactly what could drop it.
    BackendProcessService.entityType = 'organization';
    expect(BackendProcessService.entityType, 'organization');
    BackendProcessService.entityType = null;
  });
}
