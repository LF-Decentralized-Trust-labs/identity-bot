import 'dart:async';
import 'dart:io';

import 'package:agent_client/services/backend_process_service.dart';
import 'package:test/test.dart';

/// Logging out must end a core this app ADOPTED rather than spawned — the one
/// an earlier run left listening — and say so only when nothing answers.
String? _dart() {
  var d = File(Platform.resolvedExecutable).parent;
  for (var i = 0; i < 8; i++) {
    final c = File('${d.path}/dart-sdk/bin/dart');
    if (c.existsSync()) return c.path;
    final c2 = File('${d.path}/cache/dart-sdk/bin/dart');
    if (c2.existsSync()) return c2.path;
    d = d.parent;
  }
  return null;
}

void main() {
  final dart = _dart();

  test('a leftover core is ended by its data directory, and confirmed',
      () async {
    final dir = Directory.systemTemp.createTempSync('leftover_core');
    addTearDown(() => dir.deleteSync(recursive: true));
    File('${dir.path}/local-owner-secret')
        .writeAsStringSync('s' * 43); // 43 chars, as minted
    final leftover = await Process.start(
        dart!,
        [
          '--packages=${Directory.current.path}/.dart_tool/package_config.json',
          '${Directory.current.path}/test/support/a_leftover_core.dart',
          dir.path,
        ]);
    addTearDown(() => leftover.kill(ProcessSignal.sigkill));
    for (var i = 0; i < 100 && !File('${dir.path}/.pid').existsSync(); i++) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    expect(File('${dir.path}/.pid').existsSync(), isTrue);

    BackendProcessService.dataDirOverride = dir.path;
    addTearDown(() => BackendProcessService.dataDirOverride = null);
    final svc = BackendProcessService.instance;

    // The app holds no handle to it: nothing spawned it.
    expect(svc.isRunning, isFalse);
    expect(await svc.stop(), isTrue,
        reason: 'stopped, and the port no longer answers');
    final exited = await leftover.exitCode.timeout(const Duration(seconds: 5));
    expect(exited, 0);
  }, skip: dart == null ? 'no dart executable found beside flutter' : null);

  test('a core that does not prove it is this directory\'s is left alone',
      () async {
    final dir = Directory.systemTemp.createTempSync('stranger_core');
    addTearDown(() => dir.deleteSync(recursive: true));
    File('${dir.path}/local-owner-secret').writeAsStringSync('a' * 43);
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    unawaited(server.forEach((r) async {
      r.response.write('{"proof":"wrong"}');
      await r.response.close();
    }));
    File('${dir.path}/.port').writeAsStringSync('${server.port}');
    // A pid that would be fatal to signal: this very test process.
    File('${dir.path}/.pid').writeAsStringSync('$pid');
    BackendProcessService.dataDirOverride = dir.path;
    addTearDown(() => BackendProcessService.dataDirOverride = null);

    expect(await BackendProcessService.instance.stop(), isFalse,
        reason: 'something still answers, so logging out is not done');
  });

  test('nothing answering is a confirmed stop', () async {
    final dir = Directory.systemTemp.createTempSync('no_core');
    addTearDown(() => dir.deleteSync(recursive: true));
    BackendProcessService.dataDirOverride = dir.path;
    addTearDown(() => BackendProcessService.dataDirOverride = null);
    expect(await BackendProcessService.instance.stop(), isTrue);
  });
}
