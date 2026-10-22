import 'dart:io';

import 'package:agent_client/config/agent_config.dart';
import 'package:agent_client/services/backend_process_service.dart';
import 'package:agent_client/services/core_service.dart';
import 'package:agent_client/services/mobile_core_service.dart';
import 'package:agent_client/services/the_agent_this_app_talks_to.dart';
import 'package:agent_client/services/the_owner_at_this_computer.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

/// Being on this computer does not make a program the owner of the core here;
/// the secret the core was started with does. These pin that this app sends it
/// to that core, sends it nowhere else, and that no client in the package can
/// leave it off.
const _secret = 'a-local-owner-secret-for-these-tests-0123456789';

void main() {
  late List<http.BaseRequest> sent;
  late http.Client network;

  setUp(() {
    sent = [];
    network = MockClient((r) async {
      sent.add(r);
      return http.Response('{}', 200);
    });
    LocalOwnerSecret.use(_secret);
  });
  tearDown(LocalOwnerSecret.forget);

  String? carried(http.BaseRequest r) => r.headers[LocalOwnerSecret.header];

  test('a request to the core on this computer carries the secret', () async {
    await ProvingThisComputer(network)
        .get(Uri.parse('${AgentConfig.coreBaseUrl}/api/identity'));
    expect(carried(sent.single), _secret);
  });

  test('a request anywhere else never does', () async {
    final c = ProvingThisComputer(network);
    final core = Uri.parse(AgentConfig.coreBaseUrl);
    for (final url in [
      'https://relay.example.test/api/identity',
      'https://witness.example.test/oobi',
      // Another program listening on this computer is not the core.
      'http://127.0.0.1:${core.port + 1}/api/identity',
    ]) {
      await c.get(Uri.parse(url));
    }
    expect(sent.map(carried), everyElement(isNull));
  });

  test('the clients the services use carry it to the core', () async {
    await TheAgentThisAppTalksTo.clientFor(null, network)
        .get(Uri.parse('${AgentConfig.coreBaseUrl}/api/identity'));
    await CoreService(inner: network).client
        .get(Uri.parse('${AgentConfig.coreBaseUrl}/api/identity'));
    expect(sent.map(carried), everyElement(_secret));
  });

  test('a desktop app starts the core with the secret it will send', () {
    final env = <String, String>{};
    BackendProcessService.ownTheCoreAboutToStart(env);
    final given = env[LocalOwnerSecret.environmentVariable];
    expect(given, isNotNull);
    expect(given!.length, greaterThanOrEqualTo(32),
        reason: 'the core refuses a secret shorter than 32 characters');
    expect(LocalOwnerSecret.current, given);
  });

  test('a phone app hands the core the secret it will send', () {
    final args = MobileCoreService.startArguments(localOwnerSecret: _secret);
    expect(args['localOwnerSecret'], _secret);
  });

  test('an app attaching to a running core takes up the secret it wrote', () {
    final dir = Directory.systemTemp.createTempSync('owner-secret');
    addTearDown(() {
      BackendProcessService.dataDirOverride = null;
      dir.deleteSync(recursive: true);
    });
    File('${dir.path}/${LocalOwnerSecret.fileName}')
        .writeAsStringSync('written-by-the-core-0123456789abcdef\n');
    BackendProcessService.dataDirOverride = dir.path;
    LocalOwnerSecret.forget();
    expect(BackendProcessService.instance.adoptRunningCoresSecret(), isTrue);
    expect(LocalOwnerSecret.current, 'written-by-the-core-0123456789abcdef');
  });

  // One transport for every request is what makes the secret impossible to
  // forget on a request somebody adds later. A client built anywhere else in
  // the package would reach the core without it.
  test('no client in the package is built around the transport', () {
    final offenders = <String>[];
    final bare = RegExp(r'http\.Client\(\)|\bhttp\s*\.\s*(get|post|put|patch|delete|head|read)\(');
    for (final f in Directory('lib').listSync(recursive: true).whereType<File>()) {
      if (!f.path.endsWith('.dart') ||
          f.path.endsWith('the_owner_at_this_computer.dart')) {
        continue;
      }
      if (bare.hasMatch(f.readAsStringSync())) offenders.add(f.path);
    }
    expect(offenders, isEmpty,
        reason: 'build clients with ProvingThisComputer.over(...) instead');
  });
}
