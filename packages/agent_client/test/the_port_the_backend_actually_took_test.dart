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

  setUp(() {
    profile = Directory.systemTemp.createTempSync('profile');
    BackendProcessService.dataDirOverride = profile.path;
  });

  tearDown(() {
    BackendProcessService.dataDirOverride = null;
    profile.deleteSync(recursive: true);
  });

  test('it reads the port from the data directory it was given', () {
    File('${profile.path}${Platform.pathSeparator}.port').writeAsStringSync('5052');

    expect(BackendProcessService.instance.debugDiscoverActualPort(), 5052,
        reason: 'the backend wrote 5052 where it was told to keep its data, and '
            'that is the only copy there is');
  });

  // An app that sets no override still tells its backend where to keep its
  // data. The port has to be looked for in that same place, or the app waits
  // for a file in a folder the backend never writes to and gives up.
  test('with no override it looks where it told the backend to keep its data', () {
    BackendProcessService.dataDirOverride = null;
    final service = BackendProcessService.instance;

    expect(service.debugPortFilePath(),
        '${service.debugBackendDataDir()}${Platform.pathSeparator}.port');
  });

  // Guessing the default port meant a health check could reach another program
  // answering there — another Identity Agent app on the same machine — and the
  // app then talked to that identity as if it were its own.
  test('with nothing written it does not guess the default port', () {
    expect(BackendProcessService.instance.debugDiscoverActualPort(), isNull);
  });

  test('a port left from an earlier run is forgotten before the backend starts', () {
    File('${profile.path}${Platform.pathSeparator}.port').writeAsStringSync('${AgentConfig.defaultDesktopPort}');
    BackendProcessService.instance.debugForgetPort();
    expect(BackendProcessService.instance.debugDiscoverActualPort(), isNull,
        reason: 'only the backend about to start may say where it is');
  });
}
