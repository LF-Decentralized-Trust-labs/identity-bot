import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/signing_an_event.dart';
import 'package:agent_client/services/the_identity_this_device_holds.dart';
import 'package:agent_client/services/the_key_state_this_device_reads.dart';
import 'package:agent_client/services/the_key_events_this_device_makes.dart';
import 'package:agent_client/services/the_witnesses_of_this_devices_events.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;
import 'package:test/test.dart';

/// The secret a test's core is started with, as an app hands it the core it
/// starts.
const ownerSecret = 'a-secret-only-this-test-and-its-core-know';

/// The client an app reaches its core through, with the ways a core can
/// mislead it set on it.
class ACoreThatMisleads extends http.BaseClient {
  ACoreThatMisleads(this._inner);
  final http.Client _inner;

  /// The next commit is not sent to the core, and is answered with this
  /// status and refusal code instead.
  (int, String)? answerTheNextCommit;

  /// The next commit is sent, and its answer replaced with this one.
  (int, String)? replaceTheNextCommitsAnswer;

  /// The next commit reaches the core and its answer is lost, as when the
  /// connection drops after the core has the request.
  bool loseTheNextCommitsAnswer = false;

  /// Counts down one per commit; the commit that brings it to zero has its
  /// answer lost, as [loseTheNextCommitsAnswer] does for the next one.
  int? loseTheAnswerToCommitsAfter;

  /// Every commit is answered `202 waiting_for_signatures`, without reaching
  /// the core: it says it holds the event for signers that are not coming, and
  /// adds nothing.
  bool holdEveryCommit = false;

  /// Rewrites the body of a prepare request before the core sees it, so the
  /// core prepares another event than the one asked for; null leaves it as it
  /// was.
  Map<String, Object?>? Function(Map<String, Object?> asked)? alterThePrepare;

  /// How many commits were sent to this client, answered or not.
  int commits = 0;

  /// How many prepares to answer `tip_moved` without asking the core.
  int movePrepares = 0;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    request.headers['X-Local-Owner-Secret'] = ownerSecret;
    final path = request.url.path;
    final alter = alterThePrepare;
    if (path == '/api/events/prepare' &&
        alter != null &&
        request is http.Request) {
      final altered =
          alter(Map<String, Object?>.from(jsonDecode(request.body) as Map));
      if (altered != null) request.body = jsonEncode(altered);
    }
    if (path == '/api/events/commit') commits++;
    if (path == '/api/events/prepare' && movePrepares > 0) {
      movePrepares--;
      return _answer(409, 'tip_moved');
    }
    if (path == '/api/events/commit') {
      if (holdEveryCommit) {
        return http.StreamedResponse(
            Stream.value(utf8.encode(jsonEncode(
                {'status': 'waiting_for_signatures', 's': '1', 'd': 'x'}))),
            202);
      }
      final instead = answerTheNextCommit;
      if (instead != null) {
        answerTheNextCommit = null;
        return _answer(instead.$1, instead.$2);
      }
      final after = loseTheAnswerToCommitsAfter;
      if (after != null) {
        if (after == 0) {
          loseTheAnswerToCommitsAfter = null;
          loseTheNextCommitsAnswer = true;
        } else {
          loseTheAnswerToCommitsAfter = after - 1;
        }
      }
      if (loseTheNextCommitsAnswer) {
        loseTheNextCommitsAnswer = false;
        final res = await _inner.send(request);
        await res.stream.drain<void>();
        throw http.ClientException(
            'the connection dropped before the answer arrived', request.url);
      }
      final replaced = replaceTheNextCommitsAnswer;
      if (replaced != null) {
        replaceTheNextCommitsAnswer = null;
        final res = await _inner.send(request);
        await res.stream.drain<void>();
        return _answer(replaced.$1, replaced.$2);
      }
    }
    return _inner.send(request);
  }

  static http.StreamedResponse _answer(int status, String code) =>
      http.StreamedResponse(
          Stream.value(utf8.encode(jsonEncode({'error': code}))), status);
}

/// The event [body] asks the core at [base] to prepare, signed by the key
/// [seed] derives at generation [gen]: what another device holding the
/// phrase would make.
Future<SignedCopy> preparedAndSigned(http.Client client, String base,
    Uint8List seed, int gen, Map<String, Object?> body) async {
  final res = await client.post(Uri.parse('$base/api/events/prepare'),
      headers: const {'Content-Type': 'application/json'},
      body: jsonEncode(body));
  final raw = (jsonDecode(res.body) as Map)['raw_b64'] as String;
  final sig = ed.sign(
      ed.newKeyFromSeed(KeyManager.signingSeed(seed, index: gen)),
      base64Decode(raw));
  return SignedCopy(raw, [await cesrEncodeSignature(client, base, sig)]);
}

/// An interaction of [aid] after [after], prepared by the core and signed by
/// the key [seed] derives at generation [gen].
Future<SignedCopy> signedInteraction(
        http.Client client,
        String base,
        Uint8List seed,
        String aid,
        int gen,
        Place after,
        List<Object?> anchors) =>
    preparedAndSigned(client, base, seed, gen, {
      'aid': aid,
      't': 'ixn',
      'a': anchors,
      'after': {'s': after.sn.toRadixString(16), 'd': after.digest},
    });

/// Commits a signed event to the core at [base] directly.
Future<void> commitTo(String base, String rawB64, List<String> sigs) async {
  final res = await http.post(Uri.parse('$base/api/events/commit'),
      headers: const {
        'Content-Type': 'application/json',
        'X-Local-Owner-Secret': ownerSecret
      },
      body: jsonEncode({'raw_b64': rawB64, 'sigs': sigs}));
  expect(res.statusCode, anyOf(200, 201), reason: res.body);
}

/// Another core, for an identity of its own.
class ACore {
  ACore(this._process, this.base, this.client, this._km, this.logs);
  final Process _process;

  /// Everything the core wrote to its standard output and error.
  final StringBuffer logs;
  final String base;
  final ACoreThatMisleads client;
  final KeyMath _km;
  TheKeyEventsThisDeviceMakes makes(TheWitnessesOfThisDevicesEvents w) =>
      TheKeyEventsThisDeviceMakes(client, base, _km, witnesses: w);

  /// An identity's key events as a device that keeps its own record makes them
  /// and reads the key state from it, as an app does: after a restart the
  /// record and the key state are read again from what was stored.
  TheKeyEventsThisDeviceMakes makesReadingTheKeyState(Uint8List seed,
          {KeyMath? keyMath}) =>
      TheKeyEventsThisDeviceMakes(client, base, keyMath ?? _km,
          held: TheIdentityThisDeviceHolds(),
          readTheKeyState: (_) async =>
              (await TheKeyStateThisDeviceReads(client, keyMath ?? _km, base)
                      .read(seed))
                  .now);
  Future<void> close() async => _process.kill();
}

Future<ACore> anotherCore(String bin, KeyMath km) async {
  final port = 20000 + Random().nextInt(20000);
  final base = 'http://127.0.0.1:$port';
  final data = await Directory.systemTemp.createTemp('witnessed-core-data');
  final p = await Process.start(bin, [], environment: {
    ...Platform.environment,
    'PORT': '$port',
    'HOST': '127.0.0.1',
    'AGENT_DATA_DIR': data.path,
    'IDENTITY_AGENT_LOCAL_OWNER_SECRET': ownerSecret,
  });
  final logs = StringBuffer();
  p.stdout.transform(utf8.decoder).listen(logs.write);
  p.stderr.transform(utf8.decoder).listen(logs.write);
  for (var i = 0; i < 100; i++) {
    try {
      if ((await http.get(Uri.parse('$base/api/health'))).statusCode == 200) {
        break;
      }
    } catch (_) {}
    await Future<void>.delayed(const Duration(milliseconds: 100));
  }
  return ACore(p, base, ACoreThatMisleads(http.Client()), km, logs);
}
