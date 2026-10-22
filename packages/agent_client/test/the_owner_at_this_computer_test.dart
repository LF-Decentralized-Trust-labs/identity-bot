import 'dart:convert';
import 'dart:io';

import 'package:agent_client/config/agent_config.dart';
import 'package:agent_client/services/a_socket_to_the_agent_io.dart';
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
/// only to a core that has proved it holds it, sends it nowhere else, and that
/// no client or socket in the package can leave it off.
const _secret = 'a-local-owner-secret-for-these-tests-0123456789';

/// A core on [port] that holds [secret]: it answers the proof the way the real
/// core does (server.LocalOwnerProof).
http.Client coreHolding(String secret, int port, List<http.BaseRequest> sent) =>
    MockClient((r) async {
      sent.add(r);
      if (r.url.path == '/api/local-owner/proof') {
        final nonce = r.url.queryParameters['nonce']!;
        return http.Response(
            jsonEncode({'proof': LocalOwnerSecret.proof(secret, nonce, port)}),
            200);
      }
      return http.Response('{}', 200);
    });

void main() {
  late List<http.BaseRequest> sent;
  final core = AgentConfig.coreBaseUrl;
  final corePort = Uri.parse(core).port;

  setUp(() {
    sent = [];
    LocalOwnerSecret.use(_secret);
  });
  tearDown(LocalOwnerSecret.forget);

  String? carried(http.BaseRequest r) => r.headers[LocalOwnerSecret.header];

  test('the proof is the same as the core computes', () {
    // The vector server.TestTheLocalOwnerProofMatchesTheSharedVector asserts.
    expect(LocalOwnerSecret.proof(_secret, 'nonce-0123456789abcdef', 8642),
        'v4KtBBsqnFrVNMHOCMoDC4LK5nUKJW5J-k_5dHCW0U0');
  });

  test('nothing carries the secret before the core has proved itself',
      () async {
    final network = coreHolding(_secret, corePort, sent);
    await ProvingThisComputer(network).get(Uri.parse('$core/api/identity'));
    expect(carried(sent.single), isNull);
  });

  test('once the core proves itself, requests to it carry the secret',
      () async {
    final network = coreHolding(_secret, corePort, sent);
    expect(await LocalOwnerSecret.proveTheCoreAt(core, using: network), isTrue);
    expect(carried(sent.single), isNull,
        reason: 'the question itself never carries the secret');
    await ProvingThisComputer(network).get(Uri.parse('$core/api/identity'));
    expect(carried(sent.last), _secret);
  });

  test('a program holding the port that cannot prove itself gets nothing',
      () async {
    final impostor = MockClient((r) async {
      sent.add(r);
      return http.Response(jsonEncode({'proof': 'guessed'}), 200);
    });
    expect(
        await LocalOwnerSecret.proveTheCoreAt(core, using: impostor), isFalse);
    await ProvingThisComputer(impostor).get(Uri.parse('$core/api/identity'));
    expect(sent.map(carried), everyElement(isNull));
  });

  test('a program passing the question to the real core on another port fails',
      () async {
    // It relays the nonce to the real core, which answers for ITS port.
    final relaying = coreHolding(_secret, corePort + 1, sent);
    expect(
        await LocalOwnerSecret.proveTheCoreAt(core, using: relaying), isFalse);
    await ProvingThisComputer(relaying).get(Uri.parse('$core/api/identity'));
    expect(sent.map(carried), everyElement(isNull));
  });

  test('a request anywhere but the proven core never carries it', () async {
    final network = coreHolding(_secret, corePort, sent);
    await LocalOwnerSecret.proveTheCoreAt(core, using: network);
    final c = ProvingThisComputer(network);
    for (final url in [
      'https://relay.example.test/api/identity',
      'https://witness.example.test/oobi',
      'http://127.0.0.1:${corePort + 1}/api/identity',
    ]) {
      await c.get(Uri.parse(url));
    }
    expect(sent.skip(1).map(carried), everyElement(isNull));
  });

  test('the clients the services use carry it to the proven core', () async {
    final network = coreHolding(_secret, corePort, sent);
    await LocalOwnerSecret.proveTheCoreAt(core, using: network);
    sent.clear();
    await TheAgentThisAppTalksTo.clientFor(null, network)
        .get(Uri.parse('$core/api/identity'));
    await CoreService(inner: network)
        .client
        .get(Uri.parse('$core/api/identity'));
    expect(sent.map(carried), everyElement(_secret));
  });

  test('a socket to the proven core carries it, and one elsewhere does not',
      () async {
    final ws = Uri.parse(core.replaceFirst('http://', 'ws://'));
    expect(headersForSocket(ws.replace(path: '/api/ws/events')), isEmpty,
        reason: 'not before the core proves itself');
    await LocalOwnerSecret.proveTheCoreAt(core,
        using: coreHolding(_secret, corePort, sent));
    expect(headersForSocket(ws.replace(path: '/api/ws/events')),
        {LocalOwnerSecret.header: _secret});
    expect(
        headersForSocket(Uri.parse('wss://relay.example.test/api/ws/events')),
        isEmpty);
  });

  test('a socket opened to the proven core sends the secret', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    String? got;
    server.listen((req) async {
      if (req.uri.path == '/api/local-owner/proof') {
        req.response.write(jsonEncode({
          'proof': LocalOwnerSecret.proof(
              _secret, req.uri.queryParameters['nonce']!, server.port)
        }));
        await req.response.close();
        return;
      }
      got = req.headers.value(LocalOwnerSecret.header);
      (await WebSocketTransformer.upgrade(req)).close();
    });
    final origin = 'http://127.0.0.1:${server.port}';
    expect(await LocalOwnerSecret.proveTheCoreAt(origin), isTrue);
    final channel = connectToTheAgent(
        Uri.parse('ws://127.0.0.1:${server.port}/api/ws/events'));
    await channel.ready;
    await channel.sink.close();
    expect(got, _secret);
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

  group('a core already running on this profile', () {
    late Directory dir;
    late HttpServer server;
    late String serverSecret;

    setUp(() async {
      dir = Directory.systemTemp.createTempSync('owner-secret');
      BackendProcessService.dataDirOverride = dir.path;
      server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      serverSecret = 'written-by-the-core-0123456789abcdefghij';
      server.listen((req) {
        if (req.uri.path == '/api/local-owner/proof') {
          req.response.write(jsonEncode({
            'proof': LocalOwnerSecret.proof(
                serverSecret, req.uri.queryParameters['nonce']!, server.port)
          }));
        } else {
          req.response.write('{}');
        }
        req.response.close();
      });
      File('${dir.path}/.port').writeAsStringSync('${server.port}');
    });
    tearDown(() async {
      await server.close(force: true);
      BackendProcessService.dataDirOverride = null;
      AgentConfig.desktopPort = AgentConfig.defaultDesktopPort;
      dir.deleteSync(recursive: true);
    });

    test('is used when it proves the secret it wrote', () async {
      File('${dir.path}/${LocalOwnerSecret.fileName}')
          .writeAsStringSync('$serverSecret\n');
      LocalOwnerSecret.forget();
      expect(await BackendProcessService.instance.useACoreAlreadyRunningHere(),
          isTrue);
      expect(LocalOwnerSecret.current, serverSecret);
      expect(AgentConfig.desktopPort, server.port);
    });

    test('is not joined by a second core when this app cannot act for it',
        () async {
      // A stale file, or a core started before it wrote one.
      File('${dir.path}/${LocalOwnerSecret.fileName}')
          .writeAsStringSync('a-stale-secret-from-a-dead-core-01234567\n');
      expect(await BackendProcessService.instance.useACoreAlreadyRunningHere(),
          isFalse);
      expect(BackendProcessService.instance.startupError,
          contains('already running'));
    });

    test('nothing is running when nothing answers', () async {
      await server.close(force: true);
      expect(await BackendProcessService.instance.useACoreAlreadyRunningHere(),
          isNull);
    });
  });

  // One transport for every request, and one helper for every socket, is what
  // makes the secret impossible to forget on a request somebody adds later.
  test('no client or socket in the package is built around them', () {
    final offenders = <String>[];
    final bare = RegExp(
        r'http\.Client\(\)|\bhttp\s*\.\s*(get|post|put|patch|delete|head|read)\(|WebSocketChannel\.connect\(|IOWebSocketChannel\.connect\(');
    for (final f
        in Directory('lib').listSync(recursive: true).whereType<File>()) {
      if (!f.path.endsWith('.dart') ||
          f.path.endsWith('the_owner_at_this_computer.dart') ||
          f.path.contains('a_socket_to_the_agent')) {
        continue;
      }
      if (bare.hasMatch(f.readAsStringSync())) offenders.add(f.path);
    }
    expect(offenders, isEmpty,
        reason: 'build clients with ProvingThisComputer.over(...) and sockets '
            'with connectToTheAgent');
  });
}
