import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:test/test.dart';

import 'support/a_core_that_misleads.dart' show ownerSecret;
import 'support/the_core.dart';

void main() {
  late String bin;

  setUpAll(() async {
    bin = await buildTheCore('a-core-that-does-not-start', dev: true);
  });

  test('a core is started on the port the system gives it, and answers there',
      () async {
    final data = await Directory.systemTemp.createTemp('a-core-that-starts');
    addTearDown(() => data.delete(recursive: true));
    final core =
        await startTheCore(bin, dataDir: data.path, ownerSecret: ownerSecret);
    addTearDown(core.process.kill);
    final res = await http.get(Uri.parse('${core.base}/api/health'));
    expect(res.statusCode, 200);
    expect(await File('${data.path}/.port').readAsString(),
        '${Uri.parse(core.base).port}');
  });

  test(
      'a core that cannot start fails the test that started it, with what it '
      'logged', () async {
    // Its data directory would be inside a file, which no core can make.
    final dir = await Directory.systemTemp.createTemp('a-core-that-fails');
    addTearDown(() => dir.delete(recursive: true));
    final file = File('${dir.path}/not-a-directory');
    await file.writeAsString('');
    await expectLater(
        startTheCore(bin,
            dataDir: '${file.path}/data', ownerSecret: ownerSecret),
        throwsA(isA<TestFailure>()
            .having((f) => f.message, 'message', contains('exited with code'))
            .having((f) => f.message, 'message',
                contains('failed to create store directory'))));
  });

  test(
      'a core that never answers fails the test that started it, with what it '
      'logged', () async {
    // The core asked to compute instead of serve, waiting for a request that
    // never comes: it never takes a port and never answers.
    final data = await Directory.systemTemp.createTemp('a-core-that-hangs');
    addTearDown(() => data.delete(recursive: true));
    await expectLater(
        startTheCore(bin,
            dataDir: data.path,
            ownerSecret: ownerSecret,
            within: const Duration(seconds: 2),
            arguments: const ['keymath', 'never-asked']),
        throwsA(isA<TestFailure>().having((f) => f.message, 'message',
            contains('did not say which port it took within 2 s'))));
  });
}
