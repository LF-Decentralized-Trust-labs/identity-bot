import 'dart:io';

import 'package:test/test.dart';
import 'package:agent_client/services/backend_process_service.dart';
import 'package:agent_client/config/agent_config.dart';

/// Finding the port the backend settled on.
///
/// The backend steps forward when its port is taken and writes the one it got
/// into its data directory. This is how the app learns which. It used to look
/// under the backend directory instead, which was the same place only while an
/// installation kept one identity — and once each identity got its own
/// directory, nothing had written there for a long time.
///
/// The app then health checked the default port, found nothing because the
/// backend was a port or two along, and reported that its own backend had
/// failed to start.
void main() {
  late Directory profile;
  late Directory backendDir;

  setUp(() {
    profile = Directory.systemTemp.createTempSync('profile');
    backendDir = Directory.systemTemp.createTempSync('backend');
    BackendProcessService.dataDirOverride = null;
  });

  tearDown(() {
    BackendProcessService.dataDirOverride = null;
    profile.deleteSync(recursive: true);
    backendDir.deleteSync(recursive: true);
  });

  test('it reads the port from the data directory it was given', () {
    File('${profile.path}${Platform.pathSeparator}.port').writeAsStringSync('5052');
    BackendProcessService.dataDirOverride = profile.path;

    expect(BackendProcessService.instance.debugDiscoverActualPort(backendDir.path), 5052,
        reason: 'the backend wrote 5052 where it was told to keep its data, and '
            'that is the only copy there is');
  });

  test('an installation with no override still works', () {
    final data = Directory('${backendDir.path}${Platform.pathSeparator}data')
      ..createSync();
    File('${data.path}${Platform.pathSeparator}.port').writeAsStringSync('5051');

    expect(BackendProcessService.instance.debugDiscoverActualPort(backendDir.path), 5051);
  });

  test('with nothing written anywhere it falls back to the default', () {
    expect(BackendProcessService.instance.debugDiscoverActualPort(backendDir.path),
        AgentConfig.defaultDesktopPort);
  });
}
